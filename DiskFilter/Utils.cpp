#include "Utils.h"
#include "mempool/mempool.h"
#include <wchar.h>
#include "fatlbr.h"
#include <ntdddisk.h>
#include <ntddvol.h>
#include "messages.h"

extern "C" PSHORT NtBuildNumber;

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

NTSTATUS KSleep(ULONG microSecond)
{
	LARGE_INTEGER timeout = RtlConvertLongToLargeInteger(-10000 * microSecond);
	KeDelayExecutionThread(KernelMode, FALSE, &timeout);
	return STATUS_SUCCESS;
}

NTSTATUS WriteReadOnlyMemory(
	PVOID lpDest,
	PVOID lpSource,
	ULONG ulSize
)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	KSPIN_LOCK spinLock;
	KIRQL oldIrql;
	PMDL pMdlMemory;
	PVOID lpWritableAddress;

	KeInitializeSpinLock(&spinLock);
	pMdlMemory = IoAllocateMdl(lpDest, ulSize, FALSE, FALSE, NULL);
	if (!pMdlMemory)
		return status;

	MmBuildMdlForNonPagedPool(pMdlMemory);
	MmProbeAndLockPages(pMdlMemory, KernelMode, IoWriteAccess);
	lpWritableAddress = MmMapLockedPages(pMdlMemory, KernelMode);
	if (lpWritableAddress)
	{
		oldIrql = 0;
		KeAcquireSpinLock(&spinLock, &oldIrql);
		RtlCopyMemory(lpWritableAddress, lpSource, ulSize);
		KeReleaseSpinLock(&spinLock, oldIrql);
		MmUnmapLockedPages(lpWritableAddress, pMdlMemory);
		status = STATUS_SUCCESS;
	}

	MmUnlockPages(pMdlMemory);
	IoFreeMdl(pMdlMemory);
	return status;
}

#define rightrotate(w, n) ((w >> n) | (w) << (32-(n)))
#define copy_uint32(p, val) *((UINT32 *)p) = swap_endian<UINT32>((val))

void SHA256(const PVOID lpData, ULONG64 ulSize, UCHAR lpOutput[32])
{
	static const UINT32 k[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	UINT32 h0 = 0x6a09e667;
	UINT32 h1 = 0xbb67ae85;
	UINT32 h2 = 0x3c6ef372;
	UINT32 h3 = 0xa54ff53a;
	UINT32 h4 = 0x510e527f;
	UINT32 h5 = 0x9b05688c;
	UINT32 h6 = 0x1f83d9ab;
	UINT32 h7 = 0x5be0cd19;
	int r = (int)(ulSize * 8 % 512);
	int append = ((r < 448) ? (448 - r) : (448 + 512 - r)) / 8;
	ULONG64 new_len = ulSize + append + 8;
	PUCHAR buf = (PUCHAR)__malloc(new_len);
	RtlZeroMemory(buf + ulSize, append);
	RtlCopyMemory(buf, lpData, ulSize);
	buf[ulSize] = 0x80;
	UINT64 bits_len = ulSize * 8;
	for (int i = 0; i < 8; i++)
	{
		buf[ulSize + append + i] = (bits_len >> ((7 - i) * 8)) & 0xff;
	}
	UINT32 w[64];
	RtlZeroMemory(w, sizeof(w));
	size_t chunk_len = new_len / 64;
	for (int idx = 0; idx < chunk_len; idx++)
	{
		UINT32 val = 0;
		for (int i = 0; i < 64; i++)
		{
			val = val | (*(buf + idx * 64 + i) << (8 * (3 - i)));
			if (i % 4 == 3)
			{
				w[i / 4] = val;
				val = 0;
			}
		}
		for (int i = 16; i < 64; i++)
		{
			UINT32 s0 = rightrotate(w[i - 15], 7) ^ rightrotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
			UINT32 s1 = rightrotate(w[i - 2], 17) ^ rightrotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}

		UINT32 a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
		for (int i = 0; i < 64; i++)
		{
			UINT32 s_1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
			UINT32 ch = (e & f) ^ (~e & g);
			UINT32 temp1 = h + s_1 + ch + k[i] + w[i];
			UINT32 s_0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
			UINT32 maj = (a & b) ^ (a & c) ^ (b & c);
			UINT32 temp2 = s_0 + maj;
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
		h5 += f;
		h6 += g;
		h7 += h;
	}
	copy_uint32(lpOutput, h0);
	copy_uint32(lpOutput + 1, h1);
	copy_uint32(lpOutput + 2, h2);
	copy_uint32(lpOutput + 3, h3);
	copy_uint32(lpOutput + 4, h4);
	copy_uint32(lpOutput + 5, h5);
	copy_uint32(lpOutput + 6, h6);
	copy_uint32(lpOutput + 7, h7);
	__free(buf);
}

#undef rightrotate
#undef copy_uint32

BOOL bitmap_test(ULONG *bitmap, ULONGLONG index)
{
	//	return ((BYTE *)BitmapDetail)[Cluster / 8] & (1 << (Cluster % 8));
	return ((bitmap[index / 8 / sizeof(ULONG)] & (1ul << (index % (8 * sizeof(ULONG))))) ? TRUE : FALSE);
}

void bitmap_set(ULONG *bitmap, ULONGLONG index, BOOL val)
{
	if (val)
		bitmap[index / 8 / sizeof(ULONG)] |= (1ul << (index % (8 * sizeof(ULONG))));
	else
		bitmap[index / 8 / sizeof(ULONG)] &= ~(1ul << (index % (8 * sizeof(ULONG))));
}

NTSTATUS RtlAllocateUnicodeString(PUNICODE_STRING us, ULONG maxLength)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (maxLength > 0)
	{
		if ((us->Buffer = (PWSTR)__malloc(maxLength)) != NULL)
		{
			RtlZeroMemory(us->Buffer, maxLength);

			us->Length = 0;
			us->MaximumLength = (USHORT)maxLength;

			status = STATUS_SUCCESS;
		}
		else
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
		}
	}

	return status;
}

NTSTATUS GetFileHandleReadOnlyDirect(PHANDLE fileHandle, PUNICODE_STRING fileName)
{
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK IoStatusBlock;

	InitializeObjectAttributes(&oa,
		fileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	return ZwCreateFile(fileHandle,
		GENERIC_READ | SYNCHRONIZE,
		&oa,
		&IoStatusBlock,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
}

PVOID GetSystemInfo(SYSTEM_INFORMATION_CLASS InfoClass)
{
	NTSTATUS ns;
	ULONG RetSize, Size = 0x100;
	PVOID Info;

	while (1)
	{
		if ((Info = __malloc(Size)) == NULL)
			return NULL;

		ns = ZwQuerySystemInformation(InfoClass, Info, Size, &RetSize);
		if (ns == STATUS_INFO_LENGTH_MISMATCH)
		{
			__free(Info);
			Size += 0x100;
		}
		else
		{
			break;
		}
	}

	if (!NT_SUCCESS(ns))
	{
		if (Info)
			__free(Info);

		return NULL;
	}

	return Info;
}

HANDLE SearchFileHandle(PUNICODE_STRING fileName)
{
	NTSTATUS status;
	ULONG i;
	PVOID sysBuffer;
	PSYSTEM_HANDLE_INFORMATION pProcesses;
	POBJECT_NAME_INFORMATION ObjectName;

	char ObjectNameBuf[1024];
	ULONG ReturnLen;
	HANDLE hPageFile;

	ObjectName = (POBJECT_NAME_INFORMATION)ObjectNameBuf;
	ObjectName->Name.MaximumLength = 510;

	sysBuffer = GetSystemInfo(SystemHandleInformation);

	if (sysBuffer == NULL)
	{
		return (HANDLE)-1;
	}

	pProcesses = (PSYSTEM_HANDLE_INFORMATION)sysBuffer;
	for (i = 0; i < pProcesses->NumberOfHandles; i++)
	{

		if (pProcesses->Handles[i].ProcessId == (ULONG64)PsGetCurrentProcessId())
		{
			status = ZwQueryObject((HANDLE)pProcesses->Handles[i].Handle, (OBJECT_INFORMATION_CLASS)1,
				ObjectName, sizeof(ObjectNameBuf), &ReturnLen);
			if (NT_SUCCESS(status) && (RtlEqualUnicodeString(&ObjectName->Name, fileName, TRUE) == TRUE))
			{
				hPageFile = (HANDLE)pProcesses->Handles[i].Handle;
				__free(sysBuffer);
				return hPageFile;
			}
		}
	}

	__free(sysBuffer);

	return (HANDLE)-1;
}

NTSTATUS GetFileHandleReadOnly(WCHAR volume, PWCHAR path, PHANDLE fileHandle, PBOOLEAN needClose)
{
	NTSTATUS status;
	//PEPROCESS eProcess = NULL;
	WCHAR tempBuffer[MAX_PATH];
	UNICODE_STRING symbol;
	UNICODE_STRING target;
	BOOLEAN	needFree = FALSE;
	OBJECT_ATTRIBUTES oa;
	HANDLE linkHandle = NULL;
	HANDLE linkHandle1 = NULL;
	ULONG ret;

	if (!fileHandle || !needClose)
		return STATUS_UNSUCCESSFUL;

	//status = PsLookupProcessByProcessId(PsGetCurrentProcessId(), &eProcess);
	//if (!NT_SUCCESS(status))
	//	return status;

	//ObDereferenceObject(eProcess);
	// 注意，要切入到系统进程获取句柄
	//KeAttachProcess(eProcess);

	swprintf_s(tempBuffer, MAX_PATH, L"\\??\\%c:%ls", volume, path);

	RtlInitUnicodeString(&target, tempBuffer);

	status = GetFileHandleReadOnlyDirect(fileHandle, &target);
	if (NT_SUCCESS(status))
	{
		*needClose = TRUE;
	}
	// 访问拒绝，尝试从HANDLE表中获取
	else if (status == STATUS_SHARING_VIOLATION)
	{
		swprintf(tempBuffer, L"\\??\\%c:", volume);
		RtlInitUnicodeString(&symbol, tempBuffer);
		RtlAllocateUnicodeString(&target, 1024);

		needFree = TRUE;

		InitializeObjectAttributes(&oa,
			&symbol,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL);

		// 将\\??\\C:映射为真实路径\\Device\\HarddiskVolume1 这样的路径

		status = ZwOpenSymbolicLinkObject(&linkHandle, GENERIC_READ, &oa);

		if (!NT_SUCCESS(status))
		{
			goto out;
		}

		status = ZwQuerySymbolicLinkObject(linkHandle, &target, &ret);

		if (!NT_SUCCESS(status))
		{
			goto out;
		}

		while (1)
		{
			// 看是否查询出来的路径指向的还是symbolicLink
			InitializeObjectAttributes(&oa,
				&target,
				OBJ_CASE_INSENSITIVE,
				NULL,
				NULL);

			// 将\\??\\C:映射为真实路径\\Device\\HarddiskVolume1 这样的路径

			status = ZwOpenSymbolicLinkObject(&linkHandle1, GENERIC_READ, &oa);

			if (NT_SUCCESS(status))
			{
				ZwClose(linkHandle);
				linkHandle = linkHandle1;
				status = ZwQuerySymbolicLinkObject(linkHandle, &target, &ret);
				if (!NT_SUCCESS(status))
				{
					goto out;
				}
			}
			else
			{
				break;
			}
		}

		// 合并路径

		RtlAppendUnicodeToString(&target, path);

		*fileHandle = SearchFileHandle(&target);
		status = STATUS_SUCCESS;

		needClose = FALSE;
	}

	if ((HANDLE)-1 == *fileHandle)
	{
		status = STATUS_UNSUCCESSFUL;
		goto out;
	}

out:
	if (linkHandle)
		ZwClose(linkHandle);

	if (needFree && target.Buffer)
		__free(target.Buffer);

	//if (eProcess)
	//	KeDetachProcess();

	return status;
}

NTSTATUS ReadFileAlign(HANDLE FileHandle, PVOID Buffer, ULONG Length, ULONG AlignSize, LONGLONG Offset)
{
	ULONG AlignedSize = (Length / AlignSize + (Length % AlignSize ? 1 : 0)) * AlignSize;
	PUCHAR AlignedBuffer = (PUCHAR)__malloc(AlignedSize);
	if (!AlignedBuffer)
		return STATUS_INSUFFICIENT_RESOURCES;
	LARGE_INTEGER ByteOffset = { 0 };
	ByteOffset.QuadPart = Offset;
	IO_STATUS_BLOCK IoStatus = { 0 };
	NTSTATUS status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatus, AlignedBuffer, AlignedSize, &ByteOffset, NULL);
	if (!NT_SUCCESS(status))
	{
		__free(AlignedBuffer);
		return status;
	}
	RtlCopyMemory(Buffer, AlignedBuffer, Length);
	__free(AlignedBuffer);
	return status;
}

NTSTATUS GetVolumeBitmapInfo(ULONG DiskNum, ULONG PartitionNum, PVOLUME_BITMAP_BUFFER *lpBitmap)
{
	NTSTATUS status;
	HANDLE FileHandle;
	UNICODE_STRING FileName;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK IoStatusBlock;

	WCHAR VolumeName[MAX_PATH];

	if (!lpBitmap)
		return STATUS_UNSUCCESSFUL;

	swprintf(VolumeName, L"\\??\\Harddisk%dPartition%d", DiskNum, PartitionNum);

	RtlInitUnicodeString(&FileName, VolumeName);

	InitializeObjectAttributes(&oa, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwCreateFile(&FileHandle,
		GENERIC_ALL | SYNCHRONIZE,
		&oa,
		&IoStatusBlock,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,	// 同步读写
		NULL,
		0);

	if (NT_SUCCESS(status))
	{
		IO_STATUS_BLOCK	ioBlock;
		PVOLUME_BITMAP_BUFFER pInfo = NULL;
		STARTING_LCN_INPUT_BUFFER StartingLCN;
		ULONG BitmapSize = 0;

		/*ZwFsControlFile(FileHandle,
			NULL,
			NULL,
			NULL,
			&ioBlock,
			FSCTL_LOCK_VOLUME,
			NULL, 0, NULL, 0
		);*/

		StartingLCN.StartingLcn.QuadPart = 0;
		do
		{
			BitmapSize += 1024 * 1024; // 1MB
			//BitmapSize += 10240; // 10KB

			pInfo = (PVOLUME_BITMAP_BUFFER)__malloc(BitmapSize);
			if (!pInfo)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			status = ZwFsControlFile(FileHandle,
				NULL,
				NULL,
				NULL,
				&ioBlock,
				FSCTL_GET_VOLUME_BITMAP,
				&StartingLCN,
				sizeof(StartingLCN),
				pInfo,
				BitmapSize
			);

			if (status == STATUS_BUFFER_OVERFLOW)
				__free(pInfo);
		} while (status == STATUS_BUFFER_OVERFLOW);

		if (!NT_SUCCESS(status))
		{
			if (pInfo)
				__free(pInfo);

			*lpBitmap = NULL;
		}
		else
		{
			/*
			// 跳过NTFS MFT簇
			NTFS_VOLUME_DATA_BUFFER NtfsVolumeData;
			RtlZeroMemory(&NtfsVolumeData, sizeof(NtfsVolumeData));
			status = ZwFsControlFile(FileHandle,
				NULL,
				NULL,
				NULL,
				&ioBlock,
				FSCTL_GET_NTFS_VOLUME_DATA,
				NULL,
				0,
				&NtfsVolumeData,
				sizeof(NtfsVolumeData)
			);
			if (NT_SUCCESS(status))
			{
				ULONGLONG MftZoneStart = NtfsVolumeData.MftZoneStart.QuadPart;
				ULONGLONG MftZoneEnd = NtfsVolumeData.MftZoneEnd.QuadPart;
				LogInfo("MFT Zone cluster %llu -> %llu\n", MftZoneStart, MftZoneEnd);
				for (ULONGLONG i = MftZoneStart; i <= MftZoneEnd; i++)
				{
					bitmap_set((PULONG)pInfo->Buffer, i, TRUE);
				}
				DWORD bytesRead = 0;
				ULONGLONG mftCount = NtfsVolumeData.MftValidDataLength.QuadPart / NtfsVolumeData.BytesPerFileRecordSegment;
				NTFS_FILE_RECORD_INPUT_BUFFER inputBuffer;
				ULONG outputBufferSize = sizeof(NTFS_FILE_RECORD_OUTPUT_BUFFER) + NtfsVolumeData.BytesPerFileRecordSegment - 1;
				PNTFS_FILE_RECORD_OUTPUT_BUFFER outputBuffer = (PNTFS_FILE_RECORD_OUTPUT_BUFFER)__malloc(outputBufferSize);
				PVOID bitmapDataBuffer = NULL;
				ULONG bitmapDataSize = 0;
				for (DWORD index = 0; index < 16; index++)
				{
					if (index == 8) // 跳过 $BadClus
						continue;

					RtlZeroMemory(&inputBuffer, sizeof(inputBuffer));
					RtlZeroMemory(outputBuffer, outputBufferSize);
					inputBuffer.FileReferenceNumber.LowPart = index;
					status = ZwFsControlFile(FileHandle,
						NULL,
						NULL,
						NULL,
						&ioBlock,
						FSCTL_GET_NTFS_FILE_RECORD,
						&inputBuffer,
						sizeof(inputBuffer),
						outputBuffer,
						outputBufferSize
					);
					if (!NT_SUCCESS(status))
					{
						LogWarn("Failed to read MFT record %d\n", index);
						if (index > 0)
							status = STATUS_SUCCESS;
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
									LogInfo("MFT %d: filename = %ls, parentId = %d, isDirectory = %d\n", index, filename, parentID, isDirectory);
								}
							}
							else if (typeCode == ATTR_DATA)
							{
								LogInfo("MFT %d: data is resident\n", index);
								// $Bitmap肯定不是resident
								//if (index == 6)
								//{
								//	bitmapDataSize = pAttr->Form.Resident.ValueLength;
								//	bitmapDataBuffer = __malloc(bitmapDataSize);
								//	RtlCopyMemory(bitmapDataBuffer, ptr, bitmapDataSize);
								//}
							}
						}
						else
						{
							if (typeCode == ATTR_DATA)
							{
								LogInfo("MFT %d: data is non-resident\n", index);
								if (index == 6)
								{
									bitmapDataSize = pAttr->Form.Nonresident.FileSize;
									bitmapDataBuffer = __malloc(bitmapDataSize);
									RtlZeroMemory(bitmapDataBuffer, bitmapDataSize);
								}
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
									ULONGLONG StartLCN = lcnOffset == 0 ? 0 : LCN;
									LogInfo("MFT %d: VCN %llu LCN %lld Clusters %lld\n", index, VCN, StartLCN, length);
									for (ULONGLONG i = 0; i <= length; i++)
									{
										bitmap_set((PULONG)pInfo->Buffer, StartLCN + i, TRUE);
									}

									if (index == 6)
									{
										ULONGLONG volumeOffset = LCN * NtfsVolumeData.BytesPerCluster;
										ULONGLONG offset = VCN * NtfsVolumeData.BytesPerCluster;
										ULONGLONG readLength = min(length * NtfsVolumeData.BytesPerCluster, bitmapDataSize - offset);
										status = ReadFileAlign(FileHandle, (PUCHAR)bitmapDataBuffer + offset, readLength, NtfsVolumeData.BytesPerSector, volumeOffset);
										if (!NT_SUCCESS(status))
										{
											LogWarn("Read bitmap error. Offset %lld, virtual offset %lld, read length %lld, bytes read = %d, status = 0x%.8X\n", volumeOffset, offset, readLength, bytesRead, status);
										}
										status = STATUS_SUCCESS;
									}

									VCN += length;
								}
							}
						}

						// next
						pAttr = (PATTRIBUTE_RECORD_HEADER)((PUCHAR)pAttr + pAttr->RecordLength);
					}
				}
				__free(outputBuffer);
				if (bitmapDataBuffer)
				{
					for (ULONGLONG i = 0; i < pInfo->BitmapSize.QuadPart; i++)
					{
						if (bitmap_test((PULONG)bitmapDataBuffer, i) && !bitmap_test((PULONG)pInfo->Buffer, i))
						{
							bitmap_set((PULONG)pInfo->Buffer, i, TRUE);
							LogInfo("Bitmap difference: %llu\n", i);
						}
					}
					__free(bitmapDataBuffer);
				}
				else
				{
					LogWarn("Bitmap file not found.\n");
				}
			}
			else
			{
				status = STATUS_SUCCESS;
			}
			*/
			LogInfo("Bitmap size = %llu\n", pInfo->BitmapSize.QuadPart);
			*lpBitmap = pInfo;
		}

		/*ZwFsControlFile(FileHandle,
			NULL,
			NULL,
			NULL,
			&ioBlock,
			FSCTL_UNLOCK_VOLUME,
			NULL, 0, NULL, 0
		);*/

		ZwClose(FileHandle);
	}

	return status;
}

PVOID GetFileClusterList(HANDLE hFile)
{
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;
	LARGE_INTEGER StartVcn;
	PRETRIEVAL_POINTERS_BUFFER pVcnPairs;
	ULONG ulOutPutSize = 0;
	ULONG uCounts = 200;

	StartVcn.QuadPart = 0;
	ulOutPutSize = sizeof(RETRIEVAL_POINTERS_BUFFER) + uCounts * sizeof(pVcnPairs->Extents) + sizeof(LARGE_INTEGER);
	pVcnPairs = (RETRIEVAL_POINTERS_BUFFER *)__malloc(ulOutPutSize);
	if (pVcnPairs == NULL)
	{
		return NULL;
	}

	while ((status = ZwFsControlFile(hFile, NULL, NULL, 0, &iosb,
		FSCTL_GET_RETRIEVAL_POINTERS,
		&StartVcn, sizeof(LARGE_INTEGER),
		pVcnPairs, ulOutPutSize)) == STATUS_BUFFER_OVERFLOW)
	{
		uCounts += 200;
		ulOutPutSize = sizeof(RETRIEVAL_POINTERS_BUFFER) + uCounts * sizeof(pVcnPairs->Extents) + sizeof(LARGE_INTEGER);
		__free(pVcnPairs);

		pVcnPairs = (RETRIEVAL_POINTERS_BUFFER *)__malloc(ulOutPutSize);
		if (pVcnPairs == NULL)
		{
			return FALSE;
		}
	}

	if (!NT_SUCCESS(status))
	{
		__free(pVcnPairs);
		return NULL;
	}

	return pVcnPairs;
}

#define HASH_BUFFER_SIZE (20 * 1024 * 1024) // 20MB

NTSTATUS GetImageHash(PUNICODE_STRING lpFileName, UCHAR lpHash[32])
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK StatusBlock;
	PFILE_OBJECT LocalFileObject;
	HANDLE FileHandle;
	NTSTATUS status;
	LARGE_INTEGER FileSize;
	PUCHAR Buffer = NULL;

	InitializeObjectAttributes(&ObjectAttributes, lpFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenFile(&FileHandle, GENERIC_READ, &ObjectAttributes, &StatusBlock,
		FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status))
		return status;

	status = ObReferenceObjectByHandle(FileHandle, GENERIC_READ, *IoFileObjectType, KernelMode, (PVOID *)&LocalFileObject, NULL);
	if (!NT_SUCCESS(status))
	{
		ZwClose(FileHandle);
		return status;
	}

	status = FsRtlGetFileSize(LocalFileObject, &FileSize);
	if (!NT_SUCCESS(status))
		goto out;

	LONGLONG lSize = FileSize.QuadPart;
	Buffer = (PUCHAR)__malloc(HASH_BUFFER_SIZE + 40);
	if (!Buffer)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto out;
	}
	*(LONGLONG*)Buffer = lSize;
	memset(Buffer + 8, 0, 32);
	if (lSize <= HASH_BUFFER_SIZE + 32)
	{
		status = ZwReadFile(FileHandle, NULL, NULL, NULL, &StatusBlock, Buffer + 8, (ULONG)lSize, NULL, NULL);
		if (NT_SUCCESS(status))
		{
			SHA256(Buffer, lSize + 8, lpHash);
		}
	}
	else
	{
		LONGLONG lCur = 0;
		while (lCur < lSize)
		{
			ULONG lRead = min(lSize - lCur, HASH_BUFFER_SIZE);
			status = ZwReadFile(FileHandle, NULL, NULL, NULL, &StatusBlock, Buffer + 40, lRead, NULL, NULL);
			if (!NT_SUCCESS(status))
				goto out;
			SHA256(Buffer, lRead + 40, Buffer + 8);
			lCur += lRead;
		}
		SHA256(Buffer, 40, lpHash);
	}
out:
	if (Buffer)
		__free(Buffer);
	ObDereferenceObject(LocalFileObject);
	ZwClose(FileHandle);
	return status;
}

BOOLEAN IsHashInList(PVOID lpHashList, UCHAR nListSize, const UCHAR lpHash[32])
{
	for (UCHAR i = 0; i < nListSize; i++)
	{
		PUCHAR HashPos = (PUCHAR)lpHashList + i * 32;
		if (RtlEqualMemory(HashPos, lpHash, 32))
		{
			return TRUE;
		}
	}
	return FALSE;
}

NTSTATUS GetFatFirstSectorOffset(HANDLE fileHandle, PULONGLONG firstDataSector)
{
	NTSTATUS status;
	IO_STATUS_BLOCK	IoStatusBlock;
	FAT_LBR fatLBR = { 0 };

	LARGE_INTEGER	pos;
	pos.QuadPart = 0;

	if (!firstDataSector)
	{
		return STATUS_NOT_FOUND;
	}

	status = ZwReadFile(fileHandle, NULL, NULL, NULL, &IoStatusBlock, &fatLBR, sizeof(fatLBR), &pos, NULL);

	if (NT_SUCCESS(status) && sizeof(FAT_LBR) == IoStatusBlock.Information)
	{
		DWORD dwRootDirSectors = 0;
		DWORD dwFATSz = 0;

		// Validate jump instruction to boot code. This field has two
		// allowed forms: 
		// jmpBoot[0] = 0xEB, jmpBoot[1] = 0x??, jmpBoot[2] = 0x90 
		// and
		// jmpBoot[0] = 0xE9, jmpBoot[1] = 0x??, jmpBoot[2] = 0x??
		// 0x?? indicates that any 8-bit value is allowed in that byte.
		// JmpBoot[0] = 0xEB is the more frequently used format.

		if ((fatLBR.wTrailSig != 0xAA55) ||
			((fatLBR.pbyJmpBoot[0] != 0xEB ||
				fatLBR.pbyJmpBoot[2] != 0x90) &&
				(fatLBR.pbyJmpBoot[0] != 0xE9)))
		{
			status = STATUS_NOT_FOUND;
			goto __faild;
		}

		// Compute first sector offset for the FAT volumes:		


		// First, we determine the count of sectors occupied by the
		// root directory. Note that on a FAT32 volume the BPB_RootEntCnt
		// value is always 0, so on a FAT32 volume dwRootDirSectors is
		// always 0. The 32 in the above is the size of one FAT directory
		// entry in bytes. Note also that this computation rounds up.

		dwRootDirSectors =
			(((fatLBR.bpb.wRootEntCnt * 32) +
			(fatLBR.bpb.wBytsPerSec - 1)) /
				fatLBR.bpb.wBytsPerSec);

		// The start of the data region, the first sector of cluster 2,
		// is computed as follows:

		dwFATSz = fatLBR.bpb.wFATSz16;
		if (!dwFATSz)
			dwFATSz = fatLBR.ebpb32.dwFATSz32;


		if (!dwFATSz)
		{
			status = STATUS_NOT_FOUND;
			goto __faild;
		}


		// 得到数据区开始，就是第一簇的位置
		*firstDataSector =
			(fatLBR.bpb.wRsvdSecCnt +
			(fatLBR.bpb.byNumFATs * dwFATSz) +
				dwRootDirSectors);
	}

	status = STATUS_SUCCESS;
__faild:

	return status;
}

NTSTATUS GetPartNumFromVolLetter(WCHAR Letter, PULONG DiskNum, PULONG PartitionNum)
{
	NTSTATUS status;
	HANDLE fileHandle;
	UNICODE_STRING fileName;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK IoStatusBlock;

	WCHAR volumeDosName[MAX_PATH];
	swprintf(volumeDosName, L"\\??\\%c:", Letter);

	RtlInitUnicodeString(&fileName, volumeDosName);

	InitializeObjectAttributes(&oa,
		&fileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	status = ZwCreateFile(&fileHandle,
		GENERIC_ALL | SYNCHRONIZE,
		&oa,
		&IoStatusBlock,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,	// 同步读写
		NULL,
		0);

	if (NT_SUCCESS(status))
	{
		IO_STATUS_BLOCK				ioBlock;
		PARTITION_INFORMATION_EX		partitionInfo;

		ULONG	buff[256];
		PVOLUME_DISK_EXTENTS		diskExtents;

		diskExtents = (PVOLUME_DISK_EXTENTS)buff;

		// 得到此卷所在的硬盘号，不考虑跨盘卷
		status = ZwDeviceIoControlFile(fileHandle,
			NULL,
			NULL,
			NULL,
			&ioBlock,
			IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
			NULL,
			0,
			diskExtents,
			sizeof(buff)
		);

		if (!NT_SUCCESS(status))
		{
			ZwClose(fileHandle);
			return status;
		}

		*DiskNum = diskExtents->Extents[0].DiskNumber;

		// 得到此卷的一类型，在物理硬盘的上的偏移等信息

		status = ZwDeviceIoControlFile(fileHandle,
			NULL,
			NULL,
			NULL,
			&ioBlock,
			IOCTL_DISK_GET_PARTITION_INFO_EX,
			NULL,
			0,
			&partitionInfo,
			sizeof(partitionInfo)
		);

		if (NT_SUCCESS(status))
		{
			*PartitionNum = partitionInfo.PartitionNumber;
		}

		ZwClose(fileHandle);
	}

	return status;
}

void ChangeDriveIconProtect(WCHAR volume)
{
	HANDLE	keyHandle;
	UNICODE_STRING	keyPath;
	OBJECT_ATTRIBUTES	objectAttributes;
	ULONG		ulResult;
	NTSTATUS	status;

	RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons");

	//初始化objectAttributes 
	InitializeObjectAttributes(&objectAttributes,
		&keyPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,//对大小写敏感     
		NULL,
		NULL);

	status = ZwCreateKey(&keyHandle,
		KEY_ALL_ACCESS,
		&objectAttributes,
		0,
		NULL,
		REG_OPTION_VOLATILE,   // 重启后无效
		&ulResult);

	if (NT_SUCCESS(status))
	{
		WCHAR	volumeName[10];
		HANDLE	subKey;
		swprintf(volumeName, L"%c", volume);

		RtlInitUnicodeString(&keyPath, volumeName);

		InitializeObjectAttributes(&objectAttributes,
			&keyPath,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,//对大小写敏感     
			keyHandle,
			NULL);

		status = ZwCreateKey(&subKey,
			KEY_ALL_ACCESS,
			&objectAttributes,
			0,
			NULL,
			REG_OPTION_VOLATILE,   // 重启后无效
			&ulResult);

		if (NT_SUCCESS(status))
		{
			HANDLE	subsubKey;
			RtlInitUnicodeString(&keyPath, L"DefaultIcon");

			InitializeObjectAttributes(&objectAttributes,
				&keyPath,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,//对大小写敏感     
				subKey,
				NULL);

			status = ZwCreateKey(&subsubKey,
				KEY_ALL_ACCESS,
				&objectAttributes,
				0,
				NULL,
				REG_OPTION_VOLATILE,   // 重启后无效
				&ulResult);

			if (NT_SUCCESS(status))
			{
				UNICODE_STRING	keyName;
				WCHAR iconPath[] = L"%SystemRoot%\\System32\\drivers\\DiskFilter.sys,0";
				WCHAR iconPathWin7[] = L"%SystemRoot%\\System32\\drivers\\DiskFilter.sys,1";
				WCHAR iconPathWin10[] = L"%SystemRoot%\\System32\\drivers\\DiskFilter.sys,2";

				RtlInitUnicodeString(&keyName, L"");

				if (*NtBuildNumber <= 3790)
				{
					status = ZwSetValueKey(subsubKey, &keyName, 0, REG_SZ, iconPath, sizeof(iconPath));
				}
				else if (*NtBuildNumber <= 9600)
				{
					status = ZwSetValueKey(subsubKey, &keyName, 0, REG_SZ, iconPathWin7, sizeof(iconPathWin7));
				}
				else
				{
					status = ZwSetValueKey(subsubKey, &keyName, 0, REG_SZ, iconPathWin10, sizeof(iconPathWin10));
				}

				ZwClose(subsubKey);
			}

			ZwClose(subKey);
		}

		ZwClose(keyHandle);
	}
}

wchar_t * wcsstr_n(const wchar_t *string, size_t count, const wchar_t *strCharSet)
{
	wchar_t   *cp = (wchar_t *)string;
	wchar_t   *s1, *s2;

	if (!*strCharSet)
		return ((wchar_t *)string);

	while (count && *cp)
	{
		s1 = cp;
		s2 = (wchar_t*)strCharSet;

		while (*s1 && *s2 && !(toupper(*s1) - toupper(*s2)))
			s1++, s2++;

		if (!*s2)
			return(cp);
		cp++;
		count--;
	}

	return(NULL);
}

NTSTATUS
FltReadWriteSectorsCompletion(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context
)
/*++
Routine Description:
A completion routine for use when calling the lower device objects to
which our filter deviceobject is attached.

Arguments:

DeviceObject - Pointer to deviceobject
Irp        - Pointer to a PnP Irp.
Context    - NULL or PKEVENT
Return Value:

NT Status is returned.

--*/
{
	PMDL    mdl;

	UNREFERENCED_PARAMETER(DeviceObject);

	// 
	// Free resources 
	// 

	if (Irp->AssociatedIrp.SystemBuffer && (Irp->Flags & IRP_DEALLOCATE_BUFFER)) {
		__free(Irp->AssociatedIrp.SystemBuffer);
	}
	/*
	因为这个 IRP 就是在我这层次建立的，上层本就不知道有这么一个 IRP。
	那么到这里我就要在 CompleteRoutine 中使用 IoFreeIrp()来释放掉这个 IRP，
	并返回STATUS_MORE_PROCESSING_REQUIRED不让它继续传递。这里一定要注意，
	在 CompleteRoutine函数返回后，这个 IRP 已经释放了，
	如果这个时候在有任何关于这个 IRP 的操作那么后果是灾难性的，必定导致 BSOD 错误。
	*/
	while (Irp->MdlAddress) {
		mdl = Irp->MdlAddress;
		Irp->MdlAddress = mdl->Next;
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
	}

	if (Irp->PendingReturned && (Context != NULL)) {
		*Irp->UserIosb = Irp->IoStatus;
		KeSetEvent((PKEVENT)Context, IO_DISK_INCREMENT, FALSE);
	}

	IoFreeIrp(Irp);

	// 
	// Don't touch irp any more 
	// 
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS FastFsdRequest(
	IN PDEVICE_OBJECT DeviceObject,
	IN ULONG MajorFunction,
	IN LONGLONG ByteOffset,
	OUT PVOID Buffer,
	IN ULONG Length,
	IN BOOLEAN Wait
)
{
	PIRP irp;
	IO_STATUS_BLOCK iosb;
	KEVENT event;
	NTSTATUS status;
	LARGE_INTEGER byteOffset;

	byteOffset.QuadPart = ByteOffset;
	irp = IoBuildAsynchronousFsdRequest(MajorFunction, DeviceObject,
		Buffer, Length, &byteOffset, &iosb);
	if (!irp)
		return STATUS_INSUFFICIENT_RESOURCES;

	// vista 对直接磁盘写入进行了保护, 驱动操作需要在IRP的FLAGS加上SL_FORCE_DIRECT_WRITE标志
	/*
	If the SL_FORCE_DIRECT_WRITE flag is set, kernel-mode drivers can write to volume areas that they
	normally cannot write to because of direct write blocking. Direct write blocking was implemented for
	security reasons in Windows Vista and later operating systems. This flag is checked both at the file
	system layer and storage stack layer. For more
	information about direct write blocking, see Blocking Direct Write Operations to Volumes and Disks.
	The SL_FORCE_DIRECT_WRITE flag is available in Windows Vista and later versions of Windows.
	http://msdn.microsoft.com/en-us/library/ms795960.aspx
	*/
	if (IRP_MJ_WRITE == MajorFunction)
	{
		IoGetNextIrpStackLocation(irp)->Flags |= SL_FORCE_DIRECT_WRITE;
	}

	if (Wait)
	{
		KeInitializeEvent(&event, NotificationEvent, FALSE);
		IoSetCompletionRoutine(irp, FltReadWriteSectorsCompletion,
			&event, TRUE, TRUE, TRUE);

		status = IoCallDriver(DeviceObject, irp);
		if (STATUS_PENDING == status)
		{
			KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
			status = iosb.Status;
		}
	}
	else
	{
		IoSetCompletionRoutine(irp, FltReadWriteSectorsCompletion,
			NULL, TRUE, TRUE, TRUE);
		irp->UserIosb = NULL;
		status = IoCallDriver(DeviceObject, irp);
	}

	return status;
}

void LogErrorMessage(
	IN PDEVICE_OBJECT DeviceObject,
	IN NTSTATUS ErrorCode)
{
	PIO_ERROR_LOG_PACKET errorLogEntry;

	errorLogEntry = (PIO_ERROR_LOG_PACKET)
		IoAllocateErrorLogEntry(
			DeviceObject,
			(UCHAR)(sizeof(IO_ERROR_LOG_PACKET))
		);

	if (errorLogEntry)
	{
		errorLogEntry->ErrorCode = ErrorCode;
		errorLogEntry->DumpDataSize = 0;
		errorLogEntry->NumberOfStrings = 0;
		IoWriteErrorLogEntry(errorLogEntry);
	}
}

void LogErrorMessageWithString(
	IN PDEVICE_OBJECT DeviceObject,
	IN NTSTATUS ErrorCode,
	IN PWCHAR Str,
	IN ULONG StrLength)
{
	PIO_ERROR_LOG_PACKET errorLogEntry;

	errorLogEntry = (PIO_ERROR_LOG_PACKET)
		IoAllocateErrorLogEntry(
			DeviceObject,
			(UCHAR)(sizeof(IO_ERROR_LOG_PACKET) + (StrLength + 1) * sizeof(WCHAR))
		);

	if (errorLogEntry)
	{
		errorLogEntry->ErrorCode = ErrorCode;
		errorLogEntry->DumpDataSize = 0;
		errorLogEntry->NumberOfStrings = 1;
		errorLogEntry->StringOffset = sizeof(IO_ERROR_LOG_PACKET) + errorLogEntry->DumpDataSize;
		RtlCopyMemory((PUCHAR)errorLogEntry + errorLogEntry->StringOffset, Str, (StrLength + 1) * sizeof(WCHAR));
		IoWriteErrorLogEntry(errorLogEntry);
	}
}

NTSTATUS ReadRegString(PUNICODE_STRING RegPath, PWCHAR KeyName, PWCHAR Buffer, ULONG BufferSize, PULONG RetSize)
{
	HANDLE	keyHandle;
	OBJECT_ATTRIBUTES	objectAttributes;
	ULONG		ulResult;
	NTSTATUS	status;

	LogInfo("Reading registry path %wZ\\%ls\n", RegPath, KeyName);

	InitializeObjectAttributes(&objectAttributes,
		RegPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwCreateKey(&keyHandle,
		KEY_READ,
		&objectAttributes,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		&ulResult);

	if (NT_SUCCESS(status))
	{
		UNICODE_STRING keyName;
		RtlInitUnicodeString(&keyName, KeyName);
		ULONG NeedSize = 0;
		status = ZwQueryValueKey(keyHandle, &keyName, KeyValuePartialInformation, NULL, 0, &NeedSize);
		if (NeedSize > 0)
		{
			PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)__malloc(NeedSize);
			if (info)
			{
				ULONG CurSize = 0;
				status = ZwQueryValueKey(keyHandle, &keyName, KeyValuePartialInformation, info, NeedSize, &CurSize);
				if (NT_SUCCESS(status))
				{
					if (info->Type == REG_SZ)
					{
						*RetSize = info->DataLength * sizeof(WCHAR);
						if (info->DataLength * sizeof(WCHAR) > BufferSize)
							status = STATUS_BUFFER_TOO_SMALL;
						else
							RtlCopyMemory(Buffer, info->Data, info->DataLength * sizeof(WCHAR));
					}
					else
					{
						status = STATUS_UNSUCCESSFUL;
					}
				}
				__free(info);
			}
			else
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
			}
		}

		ZwClose(keyHandle);
	}
	return status;
}

#pragma pack(push, 1)
// Starting at offset 36 into the BPB, this is the structure for a FAT12/16 FS
typedef struct _BPBFAT1216_struct {
	unsigned char     BS_DriveNumber;           // 1
	unsigned char     BS_Reserved1;             // 1
	unsigned char     BS_BootSig;               // 1
	unsigned int      BS_VolumeID;              // 4
	char     BS_VolumeLabel[11];       // 11
	char     BS_FileSystemType[8];     // 8
} BPB1216_struct;

// Starting at offset 36 into the BPB, this is the structure for a FAT32 FS
typedef struct _BPBFAT32_struct {
	unsigned int      FATSize;             // 4
	unsigned short    ExtFlags;              // 2
	unsigned short    FSVersion;             // 2
	unsigned int      RootCluster;           // 4
	unsigned short    FSInfo;                // 2
	unsigned short    BkBootSec;             // 2
	unsigned char     Reserved[12];          // 12
	unsigned char     BS_DriveNumber;            // 1
	unsigned char     BS_Reserved1;              // 1
	unsigned char     BS_BootSig;                // 1
	unsigned int      BS_VolumeID;               // 4
	char     BS_VolumeLabel[11];        // 11
	char     BS_FileSystemType[8];      // 8
} BPB32_struct;

typedef struct _BPB_struct {
	unsigned char     BS_JumpBoot[3];            // 3
	char     BS_OEMName[8];             // 8
	unsigned short    BytesPerSector;        // 2
	unsigned char     SectorsPerCluster;     // 1
	unsigned short    ReservedSectorCount;   // 2
	unsigned char     NumFATs;               // 1
	unsigned short    RootEntryCount;        // 2
	unsigned short    TotalSectors16;        // 2
	unsigned char     Media;                 // 1
	unsigned short    FATSize16;             // 2
	unsigned short    SectorsPerTrack;       // 2
	unsigned short    NumberOfHeads;         // 2
	unsigned int      HiddenSectors;         // 4
	unsigned int      TotalSectors32;        // 4
	union {
		BPB1216_struct fat16;
		BPB32_struct fat32;
	} FSTypeSpecificData;
} BPB_struct;
#pragma pack(pop)

void FormatFAT32FileSystem(HANDLE hFile, ULONGLONG FileSize, CHAR VolumeLabel[11])
{
	UCHAR sectorBuf0[512];
	UCHAR sectorBuf[512];
	BPB_struct bpb; // = (BPB_struct*)sectorBuf0;
	UINT scl, val, ssa, fat;
	IO_STATUS_BLOCK IoStatus = { 0 };
	LARGE_INTEGER Offset = { 0 };

	LogInfo("Initializating disk file with size %llu\n", FileSize);
	ULONG BufferSize = 20 * 1024 * 1024;
	PUCHAR Buffer = (PUCHAR)__malloc(BufferSize);
	memset(Buffer, 0, BufferSize);
	ULONGLONG Cur = 0;
	while (Cur < FileSize)
	{
		ULONG WriteSize = min(BufferSize, FileSize - Cur);
		Offset.QuadPart = Cur;
		ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, Buffer, WriteSize, &Offset, NULL);
		Cur += WriteSize;
	}
	__free(Buffer);
	LogInfo("Fill file ok\n");

	memset(sectorBuf0, 0x00, 0x200);
	memset(&bpb, 0, sizeof(bpb));

	// jump instruction
	bpb.BS_JumpBoot[0] = 0xEB;
	bpb.BS_JumpBoot[1] = 0x58;
	bpb.BS_JumpBoot[2] = 0x90;

	// OEM name
	memcpy(bpb.BS_OEMName, "MSDOS5.0", 8);

	// BPB
	bpb.BytesPerSector = 0x200;        // hard coded, must be a define somewhere
	bpb.SectorsPerCluster = 32;        // this may change based on drive size
	bpb.ReservedSectorCount = 32;
	bpb.NumFATs = 2;
	//bpb.RootEntryCount = 0;
	//bpb.TotalSectors16 = 0;
	bpb.Media = 0xf8;
	//bpb.FATSize16 = 0;
	bpb.SectorsPerTrack = 32;          // unknown here
	bpb.NumberOfHeads = 64;            // ?
	//bpb.HiddenSectors = 0;
	bpb.TotalSectors32 = FileSize / 0x200;
	// BPB-FAT32 Extension
	bpb.FSTypeSpecificData.fat32.FATSize = FileSize / 0x200 / 4095;
	//bpb.FSTypeSpecificData.fat32.ExtFlags = 0;
	//bpb.FSTypeSpecificData.fat32.FSVersion = 0;
	bpb.FSTypeSpecificData.fat32.RootCluster = 2;
	bpb.FSTypeSpecificData.fat32.FSInfo = 1;
	bpb.FSTypeSpecificData.fat32.BkBootSec = 6;
	//memset( bpb.FSTypeSpecificData.fat32.Reserved, 0x00, 12 );
	//bpb.FSTypeSpecificData.fat32.BS_DriveNumber = 0;
	//bpb.FSTypeSpecificData.fat32.BS_Reserved1 = 0;
	bpb.FSTypeSpecificData.fat32.BS_BootSig = 0x29;
	bpb.FSTypeSpecificData.fat32.BS_VolumeID = 0xfbf4499b;      // hardcoded volume id.  this is weird.  should be generated each time.
	memset(bpb.FSTypeSpecificData.fat32.BS_VolumeLabel, 0x20, 11);
	memcpy(bpb.FSTypeSpecificData.fat32.BS_FileSystemType, "FAT32   ", 8);
	memcpy(sectorBuf0, &bpb, sizeof(bpb));

	memcpy(sectorBuf0 + 0x5a, "\x0e\x1f\xbe\x77\x7c\xac\x22\xc0\x74\x0b\x56\xb4\x0e\xbb\x07\x00\xcd\x10\x5e\xeb\xf0\x32\xe4\xcd\x17\xcd\x19\xeb\xfeThis is not a bootable disk.  Please insert a bootable floppy and\r\npress any key to try again ... \r\n", 129);

	fat = bpb.ReservedSectorCount;

	// ending signatures
	sectorBuf0[0x1fe] = 0x55;
	sectorBuf0[0x1ff] = 0xAA;
	//write_sector(sectorBuf0, 0);
	Offset.QuadPart = 0 * 512ull;
	ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, sectorBuf0, 512, &Offset, NULL);
	LogInfo("Write boot sector ok\n");

	// set up key sectors...

	ssa = (bpb.NumFATs * bpb.FSTypeSpecificData.fat32.FATSize) + fat;

	// FSInfo sector
	memset(sectorBuf, 0x00, 0x200);
	*((UINT*)sectorBuf) = 0x41615252;
	*((UINT*)(sectorBuf + 0x1e4)) = 0x61417272;
	*((UINT*)(sectorBuf + 0x1e8)) = 0xffffffff; // last known number of free data clusters on volume
	*((UINT*)(sectorBuf + 0x1ec)) = 0xffffffff; // number of most recently known to be allocated cluster
	*((UINT*)(sectorBuf + 0x1f0)) = 0;  // reserved
	*((UINT*)(sectorBuf + 0x1f4)) = 0;  // reserved
	*((UINT*)(sectorBuf + 0x1f8)) = 0;  // reserved
	*((UINT*)(sectorBuf + 0x1fc)) = 0xaa550000;
	//write_sector(sectorBuf, 1);
	Offset.QuadPart = 1 * 512ull;
	ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, sectorBuf, 512, &Offset, NULL);
	LogInfo("Write FSInfo sector ok\n");
	fat = bpb.ReservedSectorCount;

	memset(sectorBuf, 0x00, 0x200);
	for (scl = 2; scl < bpb.SectorsPerCluster; scl++)
	{
		memset(sectorBuf, 0x00, 0x200);
		//write_sector(sectorBuf, scl);
		Offset.QuadPart = scl * 512ull;
		ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, sectorBuf, 512, &Offset, NULL);
	}
	// write backup copy of metadata
	//write_sector(sectorBuf0, 6);
	Offset.QuadPart = 6 * 512ull;
	ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, sectorBuf0, 512, &Offset, NULL);
	LogInfo("Write metadata sector ok\n");

	// make Root Directory 

// whack ROOT directory file: SSA = RSC + FN x SF + ceil((32 x RDE)/SS)  and LSN = SSA + (CN-2) x SC
// this clears the first cluster of the root directory
	memset(sectorBuf, 0x00, 0x200);     // 0x00000000 is the unallocated marker
	for (scl = ssa + bpb.SectorsPerCluster; scl >= ssa; scl--)
	{
		//write_sector(sectorBuf, scl);
		Offset.QuadPart = scl * 512ull;
		ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, sectorBuf, 512, &Offset, NULL);
	}

	/*// whack a few clusters 1/4th through the partition as well.
	// FIXME: This is a total hack, based on observed behavior.  use determinism
	for (scl=(10 * bpb->SectorsPerCluster); scl>0; scl--)
	{
		dbg_printf("wiping sector %x", scl+(bpb->TotalSectors32 / 2048));
		write_sector( sectorBuf, scl+(bpb->TotalSectors32 / 2048) );
	}*/

	memset(sectorBuf, 0x00, 0x200);     // 0x00000000 is the unallocated marker
	for (scl = fat; scl < ssa / 2; scl++)
	{
		//write_sector(sectorBuf, scl);
		Offset.QuadPart = scl * 512ull;
		ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, sectorBuf, 512, &Offset, NULL);
		//write_sector(sectorBuf, scl + (ssa / 2));
		Offset.QuadPart = (scl + (ssa / 2)) * 512ull;
		ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, sectorBuf, 512, &Offset, NULL);
	}

	//SSA = RSC + FN x SF + ceil((32 x RDE)/SS)  and LSN = SSA + (CN-2) x SC


	*((UINT*)(sectorBuf + 0x000)) = 0x0ffffff8;   // special - EOF marker
	*((UINT*)(sectorBuf + 0x004)) = 0x0fffffff;   // special and clean
	*((UINT*)(sectorBuf + 0x008)) = 0x0ffffff8;   // root directory (one cluster)
	//write_sector(sectorBuf, bpb.SectorsPerCluster);
	Offset.QuadPart = bpb.SectorsPerCluster * 512ull;
	ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, sectorBuf, 512, &Offset, NULL);
	LogInfo("Write root directory ok\n");

	memset(sectorBuf, 0x00, 0x200);
	memset(sectorBuf, 0x20, 11);
	memcpy(sectorBuf, VolumeLabel, min(strlen(VolumeLabel), 11));
	sectorBuf[11] = 0x08;
	Offset.QuadPart = ssa * 512ll;
	ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, sectorBuf, 512, &Offset, NULL);
	LogInfo("Write volume label ok\n");
}
