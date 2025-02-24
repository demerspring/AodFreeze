// Test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <stdio.h>
#include <conio.h>
#include <ShlObj.h>
#include "..\DiskFilter\Public.h"

// TEST = 1: Bitmap test
// TEST = 2: Freeze / Unfreeze
// TEST = 3: Read MFT
// TEST = 4: Dump bitmap use system api
// TEST = 5: Dump bitmap by direct read
#define TEST 5

BOOL LoadNTDriver(LPCTSTR lpszDriverName, LPCTSTR lpszDriverPath)
{
	TCHAR szDriverImagePath[256];
	GetFullPathName(lpszDriverPath, 256, szDriverImagePath, NULL);
	BOOL bRet = FALSE;
	SC_HANDLE hServiceMgr = NULL;
	SC_HANDLE hServiceDDK = NULL;

	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hServiceMgr == NULL)
	{
		bRet = FALSE;
		goto BeforeLeave;
	}
	hServiceDDK = CreateService(hServiceMgr,
		lpszDriverName,
		lpszDriverName,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_IGNORE,
		szDriverImagePath,
		NULL, NULL, NULL, NULL, NULL);
	DWORD dwRtn;
	if (hServiceDDK == NULL)
	{
		dwRtn = GetLastError();
		if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS)
		{
			bRet = FALSE;
			goto BeforeLeave;
		}
		hServiceDDK = OpenService(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
		if (hServiceDDK == NULL)
		{
			dwRtn = GetLastError();
			bRet = FALSE;
			goto BeforeLeave;
		}
	}
	bRet = StartService(hServiceDDK, NULL, NULL);
	if (!bRet)
	{
		DWORD dwRtn = GetLastError();
		if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING)
		{
			bRet = FALSE;
			goto BeforeLeave;
		}
		else
		{
			if (dwRtn == ERROR_IO_PENDING)
			{
				bRet = FALSE;
				goto BeforeLeave;
			}
			else
			{
				bRet = TRUE;
				goto BeforeLeave;
			}
		}
	}
	bRet = TRUE;
BeforeLeave:
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return bRet;
}

BOOL UnloadNTDriver(LPCTSTR szSvrName)
{
	BOOL bRet = FALSE;
	SC_HANDLE hServiceMgr = NULL;
	SC_HANDLE hServiceDDK = NULL;
	SERVICE_STATUS SvrSta;
	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hServiceMgr == NULL)
	{
		bRet = FALSE;
		goto BeforeLeave;
	}
	hServiceDDK = OpenService(hServiceMgr, szSvrName, SERVICE_ALL_ACCESS);

	if (hServiceDDK == NULL)
	{
		bRet = FALSE;
		goto BeforeLeave;
	}
	ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &SvrSta);
	DeleteService(hServiceDDK);
	bRet = TRUE;
BeforeLeave:
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return bRet;
}

typedef struct _DP_BITMAP_
{
	ULONG		bitMapSize;
	// 每个块代表多少位
	ULONG		regionSize;
	// 每个块占多少byte
	ULONG		regionBytes;
	// 这个bitmap总共有多少个块
	ULONG		regionNumber;
	// 指向bitmap存储空间的指针
	UCHAR **	buffer;
} DP_BITMAP, *PDP_BITMAP;

// 位图一次最多申请2M
#define BITMAP_SLOT_SIZE	(1024 * 1024 * 2)

void DPBitmap_Free(DP_BITMAP *bitmap);
BOOL DPBitmap_Create(
	DP_BITMAP **bitmap,		// 位图句柄指针
	ULONGLONG bitMapSize,	// 位图有多少个单位
	ULONGLONG regionBytes	// 位图粒度，分成N块，一块占多少byte
);

ULONGLONG DPBitmap_FindNext(DP_BITMAP *bitMap, ULONGLONG startIndex, BOOL set);

BOOL DPBitmap_Set(DP_BITMAP *bitMap, ULONGLONG index, BOOL set);

BOOL DPBitmap_Test(DP_BITMAP *bitMap, ULONGLONG index);

void DPBitmap_Free(DP_BITMAP *bitmap)
{
	//释放bitmap
	DWORD i = 0;

	if (NULL != bitmap)
	{
		if (NULL != bitmap->buffer)
		{
			for (i = 0; i < bitmap->regionNumber; i++)
			{
				if (NULL != bitmap->buffer[i])
				{
					//从最底层的块开始释放，所有块都轮询一次				
					free(bitmap->buffer[i]);
				}
			}
			//释放块的指针
			free(bitmap->buffer);
		}
		//释放bitmap本身
		free(bitmap);
	}
}

BOOL DPBitmap_Create(DP_BITMAP **bitmap, ULONGLONG bitMapSize, ULONGLONG regionBytes)
{
	BOOL status = FALSE;
	DP_BITMAP *myBitmap = NULL;

	//检查参数，以免使用了错误的参数导致发生处零错等错误
	if (NULL == bitmap || 0 == regionBytes || 0 == bitMapSize)
	{
		return status;
	}
	__try
	{
		*bitmap = NULL;
		//分配一个bitmap结构，这是无论如何都要分配的，这个结构相当于一个bitmap的handle	
		if (NULL == (myBitmap = (DP_BITMAP *)malloc(sizeof(DP_BITMAP))))
		{
			__leave;
		}

		//清空结构
		memset(myBitmap, 0, sizeof(DP_BITMAP));

		myBitmap->regionSize = (ULONG)(regionBytes * 8);
		if (myBitmap->regionSize > bitMapSize)
		{
			myBitmap->regionSize = (ULONG)(bitMapSize / 2);
		}
		//根据参数对结构中的成员进行赋值
		myBitmap->bitMapSize = (ULONG)bitMapSize;
		myBitmap->regionBytes = (myBitmap->regionSize / 8) + sizeof(int);

		myBitmap->regionNumber = (ULONG)(bitMapSize / myBitmap->regionSize);
		if (bitMapSize % myBitmap->regionSize)
		{
			myBitmap->regionNumber++;
		}

		//分配出regionNumber那么多个指向region的指针，这是一个指针数组
		if (NULL == (myBitmap->buffer = (UCHAR **)malloc(sizeof(UCHAR *) * myBitmap->regionNumber)))
		{
			__leave;
		}
		//清空指针数组
		memset(myBitmap->buffer, 0, sizeof(UCHAR *) * myBitmap->regionNumber);
		*bitmap = myBitmap;
		status = TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
	}
	if (!status)
	{
		if (NULL != myBitmap)
		{
			DPBitmap_Free(myBitmap);
		}
		*bitmap = NULL;
	}
	return status;
}

ULONGLONG DPBitmap_FindNext(DP_BITMAP *bitMap, ULONGLONG startIndex, BOOL set)
{
	LONG	jmpValue = set ? 0 : 0xFFFFFFFF;
	ULONG	slot = 0;

	// 遍历slot
	for (slot = startIndex / bitMap->regionSize; slot < bitMap->regionNumber; slot++)
	{
		ULONGLONG	max = 0;

		// 还没有分配
		if (!bitMap->buffer[slot])
		{
			if (set)
			{
				startIndex = (slot + 1) * bitMap->regionSize;
				continue;
			}
			else
			{
				return startIndex;
			}
		}

		for (max = min((slot + 1) * bitMap->regionSize, bitMap->bitMapSize);
			startIndex < max; )
		{
			ULONG	sIndex = startIndex % bitMap->regionSize;

			// 查找下一个置位的索引

			if (jmpValue == ((PULONG)bitMap->buffer[slot])[sIndex / 32])
			{
				// 快速跳越
				startIndex += 32 - (sIndex % 32);
				continue;
			}

			if (set == ((((PULONG)bitMap->buffer[slot])[sIndex / 32] & (1 << (sIndex % 32))) > 0))
			{
				// 找到
				return startIndex;
			}
			startIndex++;
		}
	}

	return (ULONGLONG)-1;
}

ULONGLONG DPBitmap_FindPrev(DP_BITMAP *bitMap, ULONGLONG startIndex, BOOL set)
{
	LONG	jmpValue = set ? 0 : 0xFFFFFFFF;
	ULONG	slot = 0;

	// 遍历slot
	for (slot = startIndex / bitMap->regionSize; slot >= 0; slot--)
	{
		ULONGLONG	mn = 0;

		// 还没有分配
		if (!bitMap->buffer[slot])
		{
			if (set)
			{
				if (slot == 0)
					break;

				startIndex = slot * bitMap->regionSize - 1;
				continue;
			}
			else
			{
				return startIndex;
			}
		}

		for (mn = slot * bitMap->regionSize;
			startIndex >= mn; )
		{
			ULONG	sIndex = startIndex % bitMap->regionSize;

			// 查找上一个置位的索引

			if (jmpValue == ((PULONG)bitMap->buffer[slot])[sIndex / 32])
			{
				// 快速跳越
				startIndex -= (sIndex % 32);
				if (startIndex == 0)
					return (ULONGLONG)-1;
				startIndex--;
				continue;
			}

			if (set == ((((PULONG)bitMap->buffer[slot])[sIndex / 32] & (1 << (sIndex % 32))) > 0))
			{
				// 找到
				return startIndex;
			}

			if (startIndex == 0)
				return (ULONGLONG)-1;

			startIndex--;
		}

		if (slot == 0)
			break;
	}

	return (ULONGLONG)-1;
}

BOOL DPBitmap_Set(DP_BITMAP *bitMap, ULONGLONG index, BOOL set)
{
	ULONG	slot = (ULONG)(index / bitMap->regionSize);
	if (slot > (bitMap->regionNumber - 1))
	{
		printf("WARNING: DPBitMap_Set out of range slot %d\n", slot);
		return FALSE;
	}

	if (!bitMap->buffer[slot])
	{
		if (!set)
		{
			return TRUE;
		}
		bitMap->buffer[slot] = (UCHAR *)malloc(bitMap->regionBytes);
		if (!bitMap->buffer[slot])
		{
			return FALSE;
		}
		memset(bitMap->buffer[slot], 0, bitMap->regionBytes);
	}

	index %= bitMap->regionSize;

	if (set)
		((ULONG *)bitMap->buffer[slot])[index / 32] |= (1 << (index % 32));
	else
		((ULONG *)bitMap->buffer[slot])[index / 32] &= ~(1 << (index % 32));

	return TRUE;
}

BOOL DPBitmap_Test(DP_BITMAP *bitMap, ULONGLONG index)
{
	ULONG	slot = (ULONG)(index / bitMap->regionSize);
	if (slot > (bitMap->regionNumber - 1))
	{
		printf("WARNING: DPBitMap_Test out of range slot %d\n", slot);
		return FALSE;
	}
	// 还没分配
	if (!bitMap->buffer[slot])
	{
		return FALSE;
	}

	index %= bitMap->regionSize;

	return (((ULONG *)bitMap->buffer[slot])[index / 32] & (1 << (index % 32)) ? TRUE : FALSE);
}

BOOL ReadFileAlign(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead)
{
	DWORD dwRead = 0;
	DWORD nAlignedSize = (nNumberOfBytesToRead / 512 + (nNumberOfBytesToRead % 512 ? 1 : 0)) * 512;
	PUCHAR buffer = (PUCHAR)malloc(nAlignedSize);
	if (!ReadFile(hFile, buffer, nAlignedSize, &dwRead, NULL))
	{
		*lpNumberOfBytesRead = 0;
		return FALSE;
	}
	memcpy(lpBuffer, buffer, nNumberOfBytesToRead);
	*lpNumberOfBytesRead = nNumberOfBytesToRead;
	free(buffer);
	return TRUE;
}

#pragma pack(push, 1)
typedef struct _MFT_SEGMENT_REFERENCE {
	ULONG  SegmentNumberLowPart;
	USHORT SegmentNumberHighPart;
	USHORT SequenceNumber;
} MFT_SEGMENT_REFERENCE, *PMFT_SEGMENT_REFERENCE;

typedef MFT_SEGMENT_REFERENCE FILE_REFERENCE, *PFILE_REFERENCE;

typedef struct _MULTI_SECTOR_HEADER {
	UCHAR  Signature[4];
	USHORT UpdateSequenceArrayOffset;
	USHORT UpdateSequenceArraySize;
} MULTI_SECTOR_HEADER, *PMULTI_SECTOR_HEADER;

typedef struct _FILE_RECORD_SEGMENT_HEADER {
	MULTI_SECTOR_HEADER   MultiSectorHeader;
	ULONGLONG             Reserved1;
	USHORT                SequenceNumber;
	USHORT                Reserved2;
	USHORT                FirstAttributeOffset;
	USHORT                Flags;
	ULONG                 Reserved3[2];
	FILE_REFERENCE        BaseFileRecordSegment;
	USHORT                Reserved4;
	//UPDATE_SEQUENCE_ARRAY UpdateSequenceArray;
} FILE_RECORD_SEGMENT_HEADER, *PFILE_RECORD_SEGMENT_HEADER;

typedef enum _ATTRIBUTE_TYPE_CODE {
	ATTR_STANDARD_INFORMATION = 0x10,
	ATTR_ATTRIBUTE_LIST = 0x20,
	ATTR_FILE_NAME = 0x30,
	ATTR_OBJECT_ID = 0x40,
	ATTR_VOLUME_NAME = 0x60,
	ATTR_VOLUME_INFORMATION = 0x70,
	ATTR_DATA = 0x80,
	ATTR_INDEX_ROOT = 0x90,
	ATTR_INDEX_ALLOCATION = 0xA0,
	ATTR_BITMAP = 0xB0,
	ATTR_REPARSE_POINT = 0xC0,
	ATTR_END = 0xFFFFFFFF
} ATTRIBUTE_TYPE_CODE;

#define RESIDENT_FORM 0x00
#define NONRESIDENT_FORM 0x01

typedef ULONGLONG VCN;

#define FILE_NAME_INDEX_PRESENT 0x10000000

typedef struct _ATTRIBUTE_RECORD_HEADER {
	ATTRIBUTE_TYPE_CODE TypeCode;
	ULONG               RecordLength;
	UCHAR               FormCode;
	UCHAR               NameLength;
	USHORT              NameOffset;
	USHORT              Flags;
	USHORT              Instance;
	union {
		struct {
			ULONG  ValueLength;
			USHORT ValueOffset;
			UCHAR  Reserved[2];
		} Resident;
		struct {
			VCN      LowestVcn;
			VCN      HighestVcn;
			USHORT   MappingPairsOffset;
			UCHAR    Reserved[6];
			LONGLONG AllocatedLength;
			LONGLONG FileSize;
			LONGLONG ValidDataLength;
			LONGLONG TotalAllocated;
		} Nonresident;
	} Form;
} ATTRIBUTE_RECORD_HEADER, *PATTRIBUTE_RECORD_HEADER;

typedef struct _FILE_NAME_ATTRIBUTE {
	FILE_REFERENCE ParentDirectory;
	UCHAR          Reserved[0x30];
	ULONG          FileAttributes;
	ULONG          AlignmentOrReserved;
	UCHAR          FileNameLength;
	UCHAR          Flags;
	WCHAR          FileName[1];
} FILE_NAME_ATTRIBUTE, *PFILE_NAME_ATTRIBUTE;
#pragma pack(pop)

int main()
{
#if TEST == 1
	DP_BITMAP *bitmap;
	int size = 1024;
	if (!DPBitmap_Create(&bitmap, size, 3))
	{
		printf("Failed to create bitmap\n");
		_getch();
		return 1;
	}
	while (1)
	{
		printf("Current bitmap: ");
		for (int i = 0; i < size; i++) printf("%d", (bool)DPBitmap_Test(bitmap, i));
		printf("\n");
		printf("Choice: 1: Set [index] [value] 2: FindNext [index] [value] 3: FindPrev [index] [value] 4: Fill [left] [right] [value]\n");
		int op, index, value;
		scanf_s("%d%d%d", &op, &index, &value);
		if (op == 1)
		{
			if (!DPBitmap_Set(bitmap, index, value)) printf("FAILED\n");
			else printf("OK\n");
		}
		else if (op == 2)
		{
			printf("Next value: %lld\n", DPBitmap_FindNext(bitmap, index, value));
		}
		else if (op == 3)
		{
			printf("Prev value: %lld\n", DPBitmap_FindPrev(bitmap, index, value));
		}
		else if (op == 4)
		{
			int ri = value;
			scanf_s("%d", &value);
			for (int i = index; i <= ri; i++) DPBitmap_Set(bitmap, i, value);
		}
		else
			break;
	}
	DPBitmap_Free(bitmap);
	printf("Exiting\n");
	Sleep(3000);
	return 0;
#elif TEST == 2
	HANDLE hDevice = CreateFile(DISKFILTER_WIN32_DEVICE_NAME_W, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("[-] Open device failed! Error=0x%.8X\n", GetLastError());
		_getch();
		return 1;
	}
	DISKFILTER_CONTROL buf;
	memcpy(buf.AuthorizationContext, DiskFilter_AuthorizationContext, sizeof(buf.AuthorizationContext));
	printf("Please input password: ");
	{
		for (int i = 0; i < sizeof(buf.Password) / sizeof(WCHAR); i++)
		{
			WCHAR ch = _getwch();
			if (ch == L'\r' || ch == L'\n')
			{
				buf.Password[i] = L'\0';
				putchar('\n');
				break;
			}
			buf.Password[i] = ch;
			putchar('*');
		}
	}
	buf.ControlCode = DISKFILTER_CONTROL_GETCONFIG;
	DISKFILTER_PROTECTION_CONFIG config;
	DWORD dwRet;
	if (!DeviceIoControl(hDevice, DISKFILTER_IOCTL_DRIVER_CONTROL, &buf, sizeof(buf), &config, sizeof(config), &dwRet, NULL))
	{
		printf("[-] Control device failed! Error=0x%.8X\n", GetLastError());
		_getch();
		return 1;
	}
	BOOL IsProtect = FALSE;
	if (IsProtect)
	{
		config.ProtectionFlags |= PROTECTION_ENABLE;
		config.ProtectionFlags &= ~PROTECTION_ALLOW_DRIVER_LOAD;
		config.ProtectionFlags |= PROTECTION_DRIVER_WHITELIST;
	}
	else
	{
		config.ProtectionFlags &= ~PROTECTION_ENABLE;
		config.ProtectionFlags |= PROTECTION_ALLOW_DRIVER_LOAD;
	}
	buf.ControlCode = DISKFILTER_CONTROL_SETCONFIG;
	buf.Config = config;
	if (!DeviceIoControl(hDevice, DISKFILTER_IOCTL_DRIVER_CONTROL, &buf, sizeof(buf), &config, sizeof(config), &dwRet, NULL))
	{
		printf("[-] Control device failed!\n Error=0x%.8X\n", GetLastError());
		_getch();
		return 1;
	}
	printf("[+] OK\n");
	_getch();
	return 0;
#elif TEST == 3
	HANDLE hVolume = CreateFile(L"\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hVolume == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open the volume.\n");
		return 1;
	}
	DWORD bytesRead = 0;
	NTFS_VOLUME_DATA_BUFFER volumeData;
	if (!DeviceIoControl(hVolume, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &volumeData, sizeof(volumeData), &bytesRead, NULL))
	{
		printf("Failed to read NTFS volume data.");
		CloseHandle(hVolume);
		return 1;
	}
	ULONGLONG mftCount = volumeData.MftValidDataLength.QuadPart / volumeData.BytesPerFileRecordSegment;
	NTFS_FILE_RECORD_INPUT_BUFFER inputBuffer;
	ULONG outputBufferSize = sizeof(NTFS_FILE_RECORD_OUTPUT_BUFFER) + volumeData.BytesPerFileRecordSegment - 1;
	PNTFS_FILE_RECORD_OUTPUT_BUFFER outputBuffer = (PNTFS_FILE_RECORD_OUTPUT_BUFFER)malloc(outputBufferSize);
	for (DWORD index = 0; ; ++index)
	{
		DWORD tempIndex = index;
		if (index >= 16)
			scanf_s("%d", &tempIndex);
		inputBuffer.FileReferenceNumber.LowPart = tempIndex;
		if (!DeviceIoControl(hVolume, FSCTL_GET_NTFS_FILE_RECORD, &inputBuffer, sizeof(inputBuffer), outputBuffer,
			outputBufferSize, &bytesRead, NULL))
		{
			printf("Failed to read MFT record.\n");
			continue;
		}

		// 跳过空记录
		index = outputBuffer->FileReferenceNumber.LowPart;

		PFILE_RECORD_SEGMENT_HEADER pHeader = (PFILE_RECORD_SEGMENT_HEADER)outputBuffer->FileRecordBuffer;
		if (pHeader->Flags & 0x0004) // msdn 未定义，跳过
			continue;
		if (!(pHeader->Flags & 0x0001)) // 非标准文件
			continue;
		if (pHeader->SequenceNumber == 0) // 过时条目
			continue;

		printf("%d: ", index);
		
		BOOLEAN isDirectory = FALSE;
		PATTRIBUTE_RECORD_HEADER pAttr = (PATTRIBUTE_RECORD_HEADER)((PUCHAR)pHeader + pHeader->FirstAttributeOffset);
		while (pAttr->TypeCode != ATTR_END)
		{
			ATTRIBUTE_TYPE_CODE typeCode = pAttr->TypeCode;
			UCHAR resident = pAttr->FormCode;

			if (typeCode == 0x00)
			{
				if (isDirectory)
					typeCode = ATTR_INDEX_ROOT;
				else
					typeCode = ATTR_DATA;
			}

			if (resident == 0x00)
			{
				void *ptr = (void *)((PUCHAR)pAttr + pAttr->Form.Resident.ValueOffset);

				if (typeCode == ATTR_FILE_NAME)
				{
					PFILE_NAME_ATTRIBUTE pFileName = (PFILE_NAME_ATTRIBUTE)ptr;
					if (pFileName->Flags & 0x01) // NTFS 长文件名
					{
						PWCHAR filename = pFileName->FileName;
						ULONG parentID = pFileName->ParentDirectory.SegmentNumberLowPart;
						filename[pFileName->FileNameLength] = 0;
						isDirectory = (pFileName->FileAttributes & FILE_NAME_INDEX_PRESENT) != 0;
						printf("filename = %ls, parentId = %d, isDirectory = %d\n", filename, parentID, isDirectory);
					}
				}
				else if (typeCode == ATTR_DATA)
				{
					printf("data is resident\n");
				}
				else
				{
					printf("attribute %X is resident\n", typeCode);
				}
			}
			else
			{
				if (typeCode == ATTR_DATA)
				{
					printf("data is non-resident\n");
					PUCHAR dataRun = (PUCHAR)pAttr + pAttr->Form.Nonresident.MappingPairsOffset;
					LONGLONG LCN = 0;
					ULONGLONG VCN = 0;
					while (*dataRun)
					{
						UCHAR lengthBytes = *dataRun & 0x0F;
						UCHAR offsetBytes = *dataRun >> 4;
						dataRun++;
						LONGLONG length = 0;
						memcpy(&length, dataRun, lengthBytes);
						dataRun += lengthBytes;
						LONGLONG lcnOffset = 0;
						if (offsetBytes)
						{
							if (dataRun[offsetBytes - 1] & 0x80)
								lcnOffset = -1;
							memcpy(&lcnOffset, dataRun, offsetBytes);
							dataRun += offsetBytes;
						}
						LCN += lcnOffset;
						printf("VCN %llu LCN %lld Clusters %lld\n", VCN, lcnOffset == 0 ? 0 : LCN, length);
						VCN += length;
					}
				}
				else
				{
					printf("attribute %X is non-resident\n", typeCode);
				}
			}

			// next
			pAttr = (PATTRIBUTE_RECORD_HEADER)((PUCHAR)pAttr + pAttr->RecordLength);
		}
		printf("\n");
	}
	free(outputBuffer);
	CloseHandle(hVolume);
	_getch();
	return 0;
#elif TEST == 4
	HANDLE hVolume = CreateFile(L"\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hVolume == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open the volume.\n");
		return 1;
	}
	DWORD bytesRead = 0;
	NTFS_VOLUME_DATA_BUFFER volumeData;
	if (!DeviceIoControl(hVolume, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &volumeData, sizeof(volumeData), &bytesRead, NULL))
	{
		printf("Failed to read NTFS volume data.");
		CloseHandle(hVolume);
		return 1;
	}
	DWORD bitmapMaxSize = sizeof(VOLUME_BITMAP_BUFFER) + volumeData.TotalClusters.QuadPart / 8;
	PVOLUME_BITMAP_BUFFER bitmapData = (PVOLUME_BITMAP_BUFFER)malloc(bitmapMaxSize);
	STARTING_LCN_INPUT_BUFFER startingLCN;
	startingLCN.StartingLcn.QuadPart = 0;
	if (!DeviceIoControl(hVolume, FSCTL_GET_VOLUME_BITMAP, &startingLCN, sizeof(startingLCN), bitmapData, bitmapMaxSize, &bytesRead, NULL))
	{
		printf("Failed to read bitmap.");
		CloseHandle(hVolume);
		return 1;
	}
	HANDLE hFile = CreateFile(L"Bitmap", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open the output file.\n");
		return 1;
	}
	ULONG writeSize = bitmapData->BitmapSize.QuadPart / 8 + (bitmapData->BitmapSize.QuadPart % 8 ? 1 : 0);
	DWORD bytesWrite = 0;
	if (!WriteFile(hFile, bitmapData->Buffer, writeSize, &bytesWrite, NULL))
	{
		printf("Failed to write the output file.\n");
		return 1;
	}
	CloseHandle(hFile);
	free(bitmapData);
	CloseHandle(hVolume);
	_getch();
	return 0;
#elif TEST == 5
	HANDLE hVolume = CreateFile(L"\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hVolume == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open the volume.\n");
		return 1;
	}
	DWORD bytesRead = 0;
	NTFS_VOLUME_DATA_BUFFER volumeData;
	if (!DeviceIoControl(hVolume, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &volumeData, sizeof(volumeData), &bytesRead, NULL))
	{
		printf("Failed to read NTFS volume data.");
		CloseHandle(hVolume);
		return 1;
	}
	ULONGLONG mftCount = volumeData.MftValidDataLength.QuadPart / volumeData.BytesPerFileRecordSegment;
	NTFS_FILE_RECORD_INPUT_BUFFER inputBuffer;
	ULONG outputBufferSize = sizeof(NTFS_FILE_RECORD_OUTPUT_BUFFER) + volumeData.BytesPerFileRecordSegment - 1;
	PNTFS_FILE_RECORD_OUTPUT_BUFFER outputBuffer = (PNTFS_FILE_RECORD_OUTPUT_BUFFER)malloc(outputBufferSize);
	inputBuffer.FileReferenceNumber.LowPart = 6;
	if (!DeviceIoControl(hVolume, FSCTL_GET_NTFS_FILE_RECORD, &inputBuffer, sizeof(inputBuffer), outputBuffer,
		outputBufferSize, &bytesRead, NULL))
	{
		printf("Failed to read MFT record.\n");
		CloseHandle(hVolume);
		return 1;
	}

	PFILE_RECORD_SEGMENT_HEADER pHeader = (PFILE_RECORD_SEGMENT_HEADER)outputBuffer->FileRecordBuffer;
	if ((pHeader->Flags & 0x0004) || !(pHeader->Flags & 0x0001) || pHeader->SequenceNumber == 0)
	{
		printf("Bitmap error.\n");
		CloseHandle(hVolume);
		return 1;
	}

	PVOID dataBuffer = NULL;
	ULONG dataSize = 0;

	BOOLEAN isDirectory = FALSE;
	PATTRIBUTE_RECORD_HEADER pAttr = (PATTRIBUTE_RECORD_HEADER)((PUCHAR)pHeader + pHeader->FirstAttributeOffset);
	while (pAttr->TypeCode != ATTR_END)
	{
		ATTRIBUTE_TYPE_CODE typeCode = pAttr->TypeCode;
		UCHAR resident = pAttr->FormCode;

		if (typeCode == 0x00)
		{
			if (isDirectory)
				typeCode = ATTR_INDEX_ROOT;
			else
				typeCode = ATTR_DATA;
		}

		if (resident == 0x00)
		{
			void *ptr = (void *)((PUCHAR)pAttr + pAttr->Form.Resident.ValueOffset);

			if (typeCode == ATTR_DATA)
			{
				printf("data is resident\n");
				dataSize = pAttr->Form.Resident.ValueLength;
				dataBuffer = malloc(dataSize);
				memcpy(dataBuffer, ptr, dataSize);
			}
		}
		else
		{
			if (typeCode == ATTR_DATA)
			{
				printf("data is non-resident\n");
				dataSize = pAttr->Form.Nonresident.FileSize;
				dataBuffer = malloc(dataSize);
				memset(dataBuffer, 0, dataSize);
				PUCHAR dataRun = (PUCHAR)pAttr + pAttr->Form.Nonresident.MappingPairsOffset;
				LONGLONG LCN = 0;
				ULONGLONG VCN = 0;
				while (*dataRun)
				{
					UCHAR lengthBytes = *dataRun & 0x0F;
					UCHAR offsetBytes = *dataRun >> 4;
					dataRun++;
					LONGLONG length = 0;
					memcpy(&length, dataRun, lengthBytes);
					dataRun += lengthBytes;
					LONGLONG lcnOffset = 0;
					if (offsetBytes)
					{
						if (dataRun[offsetBytes - 1] & 0x80)
							lcnOffset = -1;
						memcpy(&lcnOffset, dataRun, offsetBytes);
						dataRun += offsetBytes;
					}
					LCN += lcnOffset;
					printf("VCN %llu LCN %lld Clusters %lld\n", VCN, lcnOffset == 0 ? 0 : LCN, length);
					LARGE_INTEGER pos, newPos;
					pos.QuadPart = LCN * volumeData.BytesPerCluster;
					SetFilePointerEx(hVolume, pos, &newPos, FILE_BEGIN);
					ULONGLONG offset = VCN * volumeData.BytesPerCluster;
					ULONGLONG readLength = min(length * volumeData.BytesPerCluster, dataSize - offset);
					if (!ReadFileAlign(hVolume, (PUCHAR)dataBuffer + offset, readLength, &bytesRead))
					{
						printf("Read bitmap error. Offset %lld, virtual offset %lld, read length %lld, bytes read = %d, error = %d\n", newPos.QuadPart, offset, readLength, bytesRead, GetLastError());
					}
					VCN += length;
				}
			}
		}

		// next
		pAttr = (PATTRIBUTE_RECORD_HEADER)((PUCHAR)pAttr + pAttr->RecordLength);
	}
	free(outputBuffer);
	HANDLE hFile = CreateFile(L"Bitmap_direct", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open the output file.\n");
		return 1;
	}
	DWORD bytesWrite = 0;
	if (!WriteFile(hFile, dataBuffer, dataSize, &bytesWrite, NULL))
	{
		printf("Failed to write the output file.\n");
		return 1;
	}
	CloseHandle(hFile);
	CloseHandle(hVolume);
	_getch();
	return 0;
#endif
}
