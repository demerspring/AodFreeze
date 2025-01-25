#pragma once

#include "Pch.h"

template <typename T>
T swap_endian(T u)
{
	union
	{
		T u;
		unsigned char u8[sizeof(T)];
	} source, dest;

	source.u = u;

	for (size_t k = 0; k < sizeof(T); k++)
		dest.u8[k] = source.u8[sizeof(T) - k - 1];

	return dest.u;
}

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemNotImplemented1,
	SystemProcessesAndThreadsInformation,
	SystemCallCounts,
	SystemConfigurationInformation,
	SystemProcessorTimes,
	SystemGlobalFlag,
	SystemNotImplemented2,
	SystemModuleInformation,
	SystemLockInformation,
	SystemNotImplemented3,
	SystemNotImplemented4,
	SystemNotImplemented5,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPagefileInformation,
	SystemInstructionEmulationCounts,
	SystemInvalidInfoClass1,
	SystemCacheInformation,
	SystemPoolTagInformation,
	SystemProcessorStatistics,
	SystemDpcInformation,
	SystemNotImplemented6,
	SystemLoadImage,
	SystemUnloadImage,
	SystemTimeAdjustment,
	SystemNotImplemented7,
	SystemNotImplemented8,
	SystemNotImplemented9,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemLoadAndCallImage,
	SystemPrioritySeparation,
	SystemNotImplemented10,
	SystemNotImplemented11,
	SystemInvalidInfoClass2,
	SystemInvalidInfoClass3,
	SystemTimeZoneInformation,
	SystemLookasideInformation,
	SystemSetTimeSlipEvent,
	SystemCreateSession,
	SystemDeleteSession,
	SystemInvalidInfoClass4,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemAddVerifier,
	SystemSessionProcessesInformation
} SYSTEM_INFORMATION_CLASS;

EXTERN_C NTSTATUS NTAPI
ZwQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
);

/*NTSTATUS GetHardDiskDevice(WCHAR DiskDeviceName[], PDEVICE_OBJECT *DeviceObject);

NTSTATUS GetDeviceStack(PDEVICE_OBJECT DeviceObject, PDATA_LIST_ENTRY DeviceObjects);

NTSTATUS GetDiskMiniport(PDEVICE_OBJECT DeviceObject, PDRIVER_OBJECT *DiskMiniport);*/

#ifdef AMD64
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	USHORT /*Unique*/ProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT Handle/*Value*/;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;
#else
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	ULONG       ProcessId;
	UCHAR       ObjectTypeNumber;
	UCHAR       Flags;
	USHORT      Handle;
	PVOID       Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG32 NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;
#endif

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;                 // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

NTSTATUS KSleep(ULONG microSecond);

NTSTATUS WriteReadOnlyMemory(
	PVOID lpDest,
	PVOID lpSource,
	ULONG ulSize
);

void SHA256(const PVOID lpData, ULONG64 ulSize, UCHAR lpOutput[32]);

BOOL bitmap_test(ULONG *bitmap, ULONGLONG index);

void bitmap_set(ULONG *bitmap, ULONGLONG index, BOOL val);

NTSTATUS GetFileHandleReadOnlyDirect(PHANDLE fileHandle, PUNICODE_STRING fileName);

NTSTATUS GetFileHandleReadOnly(WCHAR volume, PWCHAR path, PHANDLE fileHandle, PBOOLEAN needClose);

NTSTATUS GetVolumeBitmapInfo(ULONG DiskNum, ULONG PartitionNum, PVOLUME_BITMAP_BUFFER *lpBitmap);

PVOID GetFileClusterList(HANDLE hFile);

NTSTATUS GetImageHash(PUNICODE_STRING lpFileName, UCHAR lpHash[32]);

BOOLEAN IsHashInList(PVOID lpHashList, UCHAR nListSize, const UCHAR lpHash[32]);

NTSTATUS GetFatFirstSectorOffset(HANDLE fileHandle, PULONGLONG firstDataSector);

NTSTATUS GetPartNumFromVolLetter(WCHAR Letter, PULONG DiskNum, PULONG PartitionNum);

void ChangeDriveIconProtect(WCHAR volume);

wchar_t * wcsstr_n(const wchar_t *string, size_t count, const wchar_t *strCharSet);

NTSTATUS FastFsdRequest(
	IN PDEVICE_OBJECT DeviceObject,
	IN ULONG MajorFunction,
	IN LONGLONG ByteOffset,
	OUT PVOID Buffer,
	IN ULONG Length,
	IN BOOLEAN Wait
);

void LogErrorMessage(
	IN PDEVICE_OBJECT DeviceObject,
	IN NTSTATUS ErrorCode);

void LogErrorMessageWithString(
	IN PDEVICE_OBJECT DeviceObject,
	IN NTSTATUS ErrorCode,
	IN PWCHAR Str,
	IN ULONG StrLength);

NTSTATUS ReadRegString(PUNICODE_STRING RegPath, PWCHAR KeyName, PWCHAR Buffer, ULONG BufferSize, PULONG RetSize);

void FormatFAT32FileSystem(HANDLE hFile, ULONGLONG FileSize, CHAR VolumeLabel[11]);
