/*
	This is a virtual disk driver for Windows that uses one or more files to
	emulate physical disks.
	Copyright (C) 1999-2015 Bo Brantén.
	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <ntifs.h>
#include <ntdddisk.h>
#include <ntddcdrm.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include <mountmgr.h>
#include <ntddvol.h>
#include <ntddscsi.h>

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenProcessToken(
	IN HANDLE       ProcessHandle,
	IN ACCESS_MASK  DesiredAccess,
	OUT PHANDLE     TokenHandle
);

NTSYSAPI
NTSTATUS
NTAPI
ZwAdjustPrivilegesToken(
	IN HANDLE               TokenHandle,
	IN BOOLEAN              DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES    NewState,
	IN ULONG                BufferLength,
	OUT PTOKEN_PRIVILEGES   PreviousState OPTIONAL,
	OUT PULONG              ReturnLength
);

/*
	This is a virtual disk driver for Windows that uses one or more files to
	emulate physical disks.
	Copyright (C) 1999-2009 Bo Brantén.
	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#define POOL_TAG 'ksiD'

#ifndef __T
#ifdef _NTDDK_
#define __T(x)  L ## x
#else
#define __T(x)  x
#endif
#endif

#ifndef _T
#define _T(x)   __T(x)
#endif

#define DEVICE_BASE_NAME    _T("\\ThawSpace")
#define DEVICE_DIR_NAME     _T("\\Device")      DEVICE_BASE_NAME
#define DEVICE_NAME_PREFIX  DEVICE_DIR_NAME     DEVICE_BASE_NAME

#define IOCTL_THAWSPACE_OPEN_FILE   CTL_CODE(FILE_DEVICE_DISK, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_THAWSPACE_CLOSE_FILE  CTL_CODE(FILE_DEVICE_DISK, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_THAWSPACE_QUERY_FILE  CTL_CODE(FILE_DEVICE_DISK, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)

typedef struct _OPEN_FILE_INFORMATION {
	LARGE_INTEGER   FileSize;
	BOOLEAN         ReadOnly;
	UCHAR           DriveLetter;
	USHORT          FileNameLength;
	WCHAR           FileName[1];
} OPEN_FILE_INFORMATION, *POPEN_FILE_INFORMATION;

#define PARAMETER_KEY           L"\\Parameters"

#define TOC_DATA_TRACK          0x04

HANDLE dir_handle;

typedef struct _DEVICE_EXTENSION {
	BOOLEAN                     media_in_device;
	UNICODE_STRING              device_name;
	ULONG                       device_number;
	DEVICE_TYPE                 device_type;
	HANDLE                      file_handle;
	UNICODE_STRING              file_name;
	LARGE_INTEGER               file_size;
	BOOLEAN                     read_only;
	PSECURITY_CLIENT_CONTEXT    security_client_context;
	LIST_ENTRY                  list_head;
	KSPIN_LOCK                  list_lock;
	KEVENT                      request_event;
	PVOID                       thread_pointer;
	BOOLEAN                     terminate_thread;
	UCHAR                       drive_letter;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

#ifdef _PREFAST_
DRIVER_INITIALIZE DriverEntry;
__drv_dispatchType(IRP_MJ_CREATE) __drv_dispatchType(IRP_MJ_CLOSE) DRIVER_DISPATCH ThawSpaceCreateClose;
__drv_dispatchType(IRP_MJ_READ) __drv_dispatchType(IRP_MJ_WRITE) DRIVER_DISPATCH ThawSpaceReadWrite;
__drv_dispatchType(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH ThawSpaceDeviceControl;
KSTART_ROUTINE ThawSpaceThread;
DRIVER_UNLOAD ThawSpaceUnload;
#endif // _PREFAST_

NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT   DriverObject,
	IN PUNICODE_STRING  RegistryPath
);

NTSTATUS
ThawSpaceCreateDevice(
	IN PDRIVER_OBJECT   DriverObject,
	IN ULONG            Number,
	IN DEVICE_TYPE      DeviceType
);

NTSTATUS ReadRegString(PUNICODE_STRING RegPath, PWCHAR KeyName, PWCHAR Buffer, ULONG BufferSize, PULONG RetSize);

VOID
ThawSpaceUnload(
	IN PDRIVER_OBJECT DriverObject
);

NTSTATUS
ThawSpaceCreateClose(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
);

NTSTATUS
ThawSpaceReadWrite(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
);

NTSTATUS
ThawSpaceDeviceControl(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
);

VOID
ThawSpaceThread(
	IN PVOID            Context
);

NTSTATUS
ThawSpaceOpenFile(
	IN PDEVICE_OBJECT            DeviceObject,
	IN POPEN_FILE_INFORMATION    open_file_information
);

NTSTATUS
ThawSpaceCloseFile(
	IN PDEVICE_OBJECT   DeviceObject
);

NTSTATUS
ThawSpaceAdjustPrivilege(
	IN ULONG            Privilege,
	IN BOOLEAN          Enable
);

#pragma code_seg("INIT")

NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT   DriverObject,
	IN PUNICODE_STRING  RegistryPath
)
{
	UNICODE_STRING              parameter_path;
	RTL_QUERY_REGISTRY_TABLE    query_table[2];
	ULONG                       n_devices;
	NTSTATUS                    status;
	UNICODE_STRING              device_dir_name;
	OBJECT_ATTRIBUTES           object_attributes;
	ULONG                       n;
	USHORT                      n_created_devices;

	DriverObject->DriverUnload = ThawSpaceUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = ThawSpaceCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = ThawSpaceCreateClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = ThawSpaceReadWrite;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = ThawSpaceReadWrite;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ThawSpaceDeviceControl;

	parameter_path.Length = 0;

	parameter_path.MaximumLength = RegistryPath->Length + sizeof(PARAMETER_KEY);

	parameter_path.Buffer = (PWSTR)ExAllocatePoolWithTag(PagedPool, parameter_path.MaximumLength, POOL_TAG);

	if (parameter_path.Buffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlCopyUnicodeString(&parameter_path, RegistryPath);

	RtlAppendUnicodeToString(&parameter_path, PARAMETER_KEY);

	RtlZeroMemory(&query_table[0], sizeof(query_table));

	query_table[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED;
	query_table[0].Name = L"NumberOfDevices";
	query_table[0].EntryContext = &n_devices;

	status = RtlQueryRegistryValues(
		RTL_REGISTRY_ABSOLUTE,
		parameter_path.Buffer,
		&query_table[0],
		NULL,
		NULL
	);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("ThawSpace: Query registry failed.\n");
		return status;
	}

	RtlInitUnicodeString(&device_dir_name, DEVICE_DIR_NAME);

	InitializeObjectAttributes(
		&object_attributes,
		&device_dir_name,
		OBJ_PERMANENT,
		NULL,
		NULL
	);

	status = ZwCreateDirectoryObject(
		&dir_handle,
		DIRECTORY_ALL_ACCESS,
		&object_attributes
	);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	ZwMakeTemporaryObject(dir_handle);

	for (n = 0, n_created_devices = 0; n < n_devices; n++)
	{
		status = ThawSpaceCreateDevice(DriverObject, n, FILE_DEVICE_DISK);

		if (NT_SUCCESS(status))
		{
			n_created_devices++;
		}
	}

	PDEVICE_OBJECT CurDevice = DriverObject->DeviceObject;
	for (n = 0; n < n_created_devices && CurDevice; n++)
	{
		WCHAR KeyName[256];
		swprintf_s(KeyName, 256, L"Device%d", n);
		ULONG NeedSize = 0;
		status = ReadRegString(&parameter_path, KeyName, NULL, 0, &NeedSize);
		if (NeedSize > 0)
		{
			ULONG CurSize = 0;
			PWCHAR Buffer = ExAllocatePoolWithTag(NonPagedPool, NeedSize, POOL_TAG);
			if (Buffer != NULL)
			{
				ReadRegString(&parameter_path, KeyName, Buffer, NeedSize, &CurSize);
				if (CurSize > 2)
				{
					POPEN_FILE_INFORMATION ofn = ExAllocatePoolWithTag(NonPagedPool, sizeof(OPEN_FILE_INFORMATION) + NeedSize + 10 * sizeof(WCHAR), POOL_TAG);
					ofn->DriveLetter = (UCHAR)toupper(Buffer[0]);
					swprintf_s(ofn->FileName, NeedSize / sizeof(WCHAR) + 10, L"\\??\\%s", Buffer + 2);
					ofn->FileNameLength = (USHORT)wcslen(ofn->FileName);
					ofn->ReadOnly = FALSE;
					ofn->FileSize.QuadPart = 0;
					ThawSpaceOpenFile(CurDevice, ofn);
					ExFreePoolWithTag(ofn, POOL_TAG);
					CurDevice = CurDevice->NextDevice;
				}
			}
		}
	}

	ExFreePool(parameter_path.Buffer);

	return STATUS_SUCCESS;
}

NTSTATUS
ThawSpaceCreateDevice(
	IN PDRIVER_OBJECT   DriverObject,
	IN ULONG            Number,
	IN DEVICE_TYPE      DeviceType
)
{
	UNICODE_STRING      device_name;
	NTSTATUS            status;
	PDEVICE_OBJECT      device_object;
	PDEVICE_EXTENSION   device_extension;
	HANDLE              thread_handle;
	UNICODE_STRING      sddl;

	ASSERT(DriverObject != NULL);

	device_name.Buffer = (PWCHAR)ExAllocatePoolWithTag(PagedPool, MAXIMUM_FILENAME_LENGTH * 2, POOL_TAG);

	if (device_name.Buffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	device_name.Length = 0;
	device_name.MaximumLength = MAXIMUM_FILENAME_LENGTH * 2;

	RtlUnicodeStringPrintf(&device_name, DEVICE_NAME_PREFIX L"%u", Number);

	RtlInitUnicodeString(&sddl, _T("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;BU)"));

	status = IoCreateDeviceSecure(
		DriverObject,
		sizeof(DEVICE_EXTENSION),
		&device_name,
		DeviceType,
		0,
		FALSE,
		&sddl,
		NULL,
		&device_object
	);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(device_name.Buffer);
		return status;
	}

	device_object->Flags |= DO_DIRECT_IO;

	device_extension = (PDEVICE_EXTENSION)device_object->DeviceExtension;

	device_extension->media_in_device = FALSE;

	device_extension->device_name.Length = device_name.Length;
	device_extension->device_name.MaximumLength = device_name.MaximumLength;
	device_extension->device_name.Buffer = device_name.Buffer;
	device_extension->device_number = Number;
	device_extension->device_type = DeviceType;

	InitializeListHead(&device_extension->list_head);

	KeInitializeSpinLock(&device_extension->list_lock);

	KeInitializeEvent(
		&device_extension->request_event,
		SynchronizationEvent,
		FALSE
	);

	device_extension->terminate_thread = FALSE;

	status = PsCreateSystemThread(
		&thread_handle,
		(ACCESS_MASK)0L,
		NULL,
		NULL,
		NULL,
		ThawSpaceThread,
		device_object
	);

	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(device_object);
		ExFreePool(device_name.Buffer);
		return status;
	}

	status = ObReferenceObjectByHandle(
		thread_handle,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		&device_extension->thread_pointer,
		NULL
	);

	if (!NT_SUCCESS(status))
	{
		ZwClose(thread_handle);

		device_extension->terminate_thread = TRUE;

		KeSetEvent(
			&device_extension->request_event,
			(KPRIORITY)0,
			FALSE
		);

		IoDeleteDevice(device_object);

		ExFreePool(device_name.Buffer);

		return status;
	}

	ZwClose(thread_handle);

	return STATUS_SUCCESS;
}

NTSTATUS ReadRegString(PUNICODE_STRING RegPath, PWCHAR KeyName, PWCHAR Buffer, ULONG BufferSize, PULONG RetSize)
{
	HANDLE	keyHandle;
	OBJECT_ATTRIBUTES	objectAttributes;
	ULONG		ulResult;
	NTSTATUS	status;

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
			PKEY_VALUE_PARTIAL_INFORMATION info = ExAllocatePoolWithTag(NonPagedPool, NeedSize, POOL_TAG);
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
				ExFreePoolWithTag(info, POOL_TAG);
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

#pragma code_seg("PAGE")

PDEVICE_OBJECT
ThawSpaceDeleteDevice(
	IN PDEVICE_OBJECT DeviceObject
)
{
	PDEVICE_EXTENSION   device_extension;
	PDEVICE_OBJECT      next_device_object;

	PAGED_CODE();

	ASSERT(DeviceObject != NULL);

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	device_extension->terminate_thread = TRUE;

	KeSetEvent(
		&device_extension->request_event,
		(KPRIORITY)0,
		FALSE
	);

	KeWaitForSingleObject(
		device_extension->thread_pointer,
		Executive,
		KernelMode,
		FALSE,
		NULL
	);

	ObDereferenceObject(device_extension->thread_pointer);

	if (device_extension->device_name.Buffer != NULL)
	{
		ExFreePool(device_extension->device_name.Buffer);
	}

	if (device_extension->security_client_context != NULL)
	{
		SeDeleteClientSecurity(device_extension->security_client_context);
		ExFreePool(device_extension->security_client_context);
	}

#pragma prefast( suppress: 28175, "allowed in unload" )
	next_device_object = DeviceObject->NextDevice;

	IoDeleteDevice(DeviceObject);

	return next_device_object;
}

VOID
ThawSpaceUnload(
	IN PDRIVER_OBJECT DriverObject
)
{
	PDEVICE_OBJECT device_object;

	PAGED_CODE();

	device_object = DriverObject->DeviceObject;

	while (device_object)
	{
		ThawSpaceCloseFile(device_object);
		device_object = ThawSpaceDeleteDevice(device_object);
	}

	ZwClose(dir_handle);
}

#pragma code_seg() // end "PAGE"

NTSTATUS
ThawSpaceCreateClose(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = FILE_OPENED;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS
ThawSpaceReadWrite(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
)
{
	PDEVICE_EXTENSION   device_extension;
	PIO_STACK_LOCATION  io_stack;

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	if (!device_extension->media_in_device)
	{
		Irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return STATUS_NO_MEDIA_IN_DEVICE;
	}

	io_stack = IoGetCurrentIrpStackLocation(Irp);

	if (io_stack->Parameters.Read.Length == 0)
	{
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return STATUS_SUCCESS;
	}

	IoMarkIrpPending(Irp);

	ExInterlockedInsertTailList(
		&device_extension->list_head,
		&Irp->Tail.Overlay.ListEntry,
		&device_extension->list_lock
	);

	KeSetEvent(
		&device_extension->request_event,
		(KPRIORITY)0,
		FALSE
	);

	return STATUS_PENDING;
}

NTSTATUS
ThawSpaceDeviceControl(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
)
{
	PDEVICE_EXTENSION   device_extension;
	PIO_STACK_LOCATION  io_stack;
	NTSTATUS            status;

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	io_stack = IoGetCurrentIrpStackLocation(Irp);

	if (!device_extension->media_in_device &&
		io_stack->Parameters.DeviceIoControl.IoControlCode !=
		IOCTL_THAWSPACE_OPEN_FILE)
	{
		Irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return STATUS_NO_MEDIA_IN_DEVICE;
	}

	switch (io_stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_THAWSPACE_OPEN_FILE:
	{
		SECURITY_QUALITY_OF_SERVICE security_quality_of_service;

		if (device_extension->media_in_device)
		{
			KdPrint(("ThawSpace: IOCTL_FILE_DISK_OPEN_FILE: Media already opened.\n"));

			status = STATUS_INVALID_DEVICE_REQUEST;
			Irp->IoStatus.Information = 0;
			break;
		}

		if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
			sizeof(OPEN_FILE_INFORMATION))
		{
			status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
			break;
		}

		if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
			sizeof(OPEN_FILE_INFORMATION) +
			((POPEN_FILE_INFORMATION)Irp->AssociatedIrp.SystemBuffer)->FileNameLength -
			sizeof(UCHAR))
		{
			status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
			break;
		}

		if (device_extension->security_client_context != NULL)
		{
			SeDeleteClientSecurity(device_extension->security_client_context);
		}
		else
		{
			device_extension->security_client_context =
				ExAllocatePoolWithTag(NonPagedPool, sizeof(SECURITY_CLIENT_CONTEXT), POOL_TAG);
		}

		RtlZeroMemory(&security_quality_of_service, sizeof(SECURITY_QUALITY_OF_SERVICE));

		security_quality_of_service.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
		security_quality_of_service.ImpersonationLevel = SecurityImpersonation;
		security_quality_of_service.ContextTrackingMode = SECURITY_STATIC_TRACKING;
		security_quality_of_service.EffectiveOnly = FALSE;

		SeCreateClientSecurity(
			PsGetCurrentThread(),
			&security_quality_of_service,
			FALSE,
			device_extension->security_client_context
		);

		IoMarkIrpPending(Irp);

		ExInterlockedInsertTailList(
			&device_extension->list_head,
			&Irp->Tail.Overlay.ListEntry,
			&device_extension->list_lock
		);

		KeSetEvent(
			&device_extension->request_event,
			(KPRIORITY)0,
			FALSE
		);

		status = STATUS_PENDING;

		break;
	}

	case IOCTL_THAWSPACE_CLOSE_FILE:
	{
		IoMarkIrpPending(Irp);

		ExInterlockedInsertTailList(
			&device_extension->list_head,
			&Irp->Tail.Overlay.ListEntry,
			&device_extension->list_lock
		);

		KeSetEvent(
			&device_extension->request_event,
			(KPRIORITY)0,
			FALSE
		);

		status = STATUS_PENDING;

		break;
	}

	case IOCTL_THAWSPACE_QUERY_FILE:
	{
		POPEN_FILE_INFORMATION open_file_information;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(OPEN_FILE_INFORMATION) + device_extension->file_name.Length - sizeof(WCHAR))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		open_file_information = (POPEN_FILE_INFORMATION)Irp->AssociatedIrp.SystemBuffer;

		open_file_information->FileSize.QuadPart = device_extension->file_size.QuadPart;
		open_file_information->ReadOnly = device_extension->read_only;
		open_file_information->FileNameLength = device_extension->file_name.Length / sizeof(WCHAR);

		RtlCopyMemory(
			open_file_information->FileName,
			device_extension->file_name.Buffer,
			device_extension->file_name.Length
		);

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(OPEN_FILE_INFORMATION) +
			open_file_information->FileNameLength - sizeof(UCHAR);

		break;
	}

	case IOCTL_DISK_CHECK_VERIFY:
	case IOCTL_CDROM_CHECK_VERIFY:
	case IOCTL_STORAGE_CHECK_VERIFY:
	case IOCTL_STORAGE_CHECK_VERIFY2:
	{
		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		break;
	}

	case IOCTL_DISK_GET_DRIVE_GEOMETRY:
	case IOCTL_CDROM_GET_DRIVE_GEOMETRY:
	{
		PDISK_GEOMETRY  disk_geometry;
		ULONGLONG       length;
		ULONG           sector_size;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(DISK_GEOMETRY))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		disk_geometry = (PDISK_GEOMETRY)Irp->AssociatedIrp.SystemBuffer;

		length = device_extension->file_size.QuadPart;

		sector_size = 512;

		disk_geometry->Cylinders.QuadPart = length / sector_size / 32 / 2;
		disk_geometry->MediaType = FixedMedia;
		disk_geometry->TracksPerCylinder = 2;
		disk_geometry->SectorsPerTrack = 32;
		disk_geometry->BytesPerSector = sector_size;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(DISK_GEOMETRY);

		break;
	}

	case IOCTL_DISK_GET_LENGTH_INFO:
	{
		PGET_LENGTH_INFORMATION get_length_information;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(GET_LENGTH_INFORMATION))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		get_length_information = (PGET_LENGTH_INFORMATION)Irp->AssociatedIrp.SystemBuffer;

		get_length_information->Length.QuadPart = device_extension->file_size.QuadPart;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(GET_LENGTH_INFORMATION);

		break;
	}

	case IOCTL_DISK_GET_PARTITION_INFO:
	{
		PPARTITION_INFORMATION  partition_information;
		ULONGLONG               length;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(PARTITION_INFORMATION))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		partition_information = (PPARTITION_INFORMATION)Irp->AssociatedIrp.SystemBuffer;

		length = device_extension->file_size.QuadPart;

		partition_information->StartingOffset.QuadPart = 0;
		partition_information->PartitionLength.QuadPart = length;
		partition_information->HiddenSectors = 1;
		partition_information->PartitionNumber = 0;
		partition_information->PartitionType = 0;
		partition_information->BootIndicator = FALSE;
		partition_information->RecognizedPartition = FALSE;
		partition_information->RewritePartition = FALSE;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(PARTITION_INFORMATION);

		break;
	}

	case IOCTL_DISK_GET_PARTITION_INFO_EX:
	{
		PPARTITION_INFORMATION_EX   partition_information_ex;
		ULONGLONG                   length;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(PARTITION_INFORMATION_EX))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		partition_information_ex = (PPARTITION_INFORMATION_EX)Irp->AssociatedIrp.SystemBuffer;

		length = device_extension->file_size.QuadPart;

		partition_information_ex->PartitionStyle = PARTITION_STYLE_MBR;
		partition_information_ex->StartingOffset.QuadPart = 0;
		partition_information_ex->PartitionLength.QuadPart = length;
		partition_information_ex->PartitionNumber = 0;
		partition_information_ex->RewritePartition = FALSE;
		partition_information_ex->Mbr.PartitionType = 0;
		partition_information_ex->Mbr.BootIndicator = FALSE;
		partition_information_ex->Mbr.RecognizedPartition = FALSE;
		partition_information_ex->Mbr.HiddenSectors = 1;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(PARTITION_INFORMATION_EX);

		break;
	}

	case IOCTL_DISK_IS_WRITABLE:
	{
		if (!device_extension->read_only)
		{
			status = STATUS_SUCCESS;
		}
		else
		{
			status = STATUS_MEDIA_WRITE_PROTECTED;
		}
		Irp->IoStatus.Information = 0;
		break;
	}

	case IOCTL_DISK_MEDIA_REMOVAL:
	case IOCTL_STORAGE_MEDIA_REMOVAL:
	{
		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		break;
	}

	case IOCTL_CDROM_READ_TOC:
	{
		PCDROM_TOC cdrom_toc;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(CDROM_TOC))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		cdrom_toc = (PCDROM_TOC)Irp->AssociatedIrp.SystemBuffer;

		RtlZeroMemory(cdrom_toc, sizeof(CDROM_TOC));

		cdrom_toc->FirstTrack = 1;
		cdrom_toc->LastTrack = 1;
		cdrom_toc->TrackData[0].Control = TOC_DATA_TRACK;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(CDROM_TOC);

		break;
	}

	case IOCTL_CDROM_GET_LAST_SESSION:
	{
		PCDROM_TOC_SESSION_DATA cdrom_toc_s_d;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(CDROM_TOC_SESSION_DATA))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		cdrom_toc_s_d = (PCDROM_TOC_SESSION_DATA)Irp->AssociatedIrp.SystemBuffer;

		RtlZeroMemory(cdrom_toc_s_d, sizeof(CDROM_TOC_SESSION_DATA));

		cdrom_toc_s_d->FirstCompleteSession = 1;
		cdrom_toc_s_d->LastCompleteSession = 1;
		cdrom_toc_s_d->TrackData[0].Control = TOC_DATA_TRACK;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(CDROM_TOC_SESSION_DATA);

		break;
	}

	case IOCTL_DISK_SET_PARTITION_INFO:
	{
		if (device_extension->read_only)
		{
			status = STATUS_MEDIA_WRITE_PROTECTED;
			Irp->IoStatus.Information = 0;
			break;
		}

		if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
			sizeof(SET_PARTITION_INFORMATION))
		{
			status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
			break;
		}

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;

		break;
	}

	case IOCTL_DISK_VERIFY:
	{
		PVERIFY_INFORMATION verify_information;

		if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
			sizeof(VERIFY_INFORMATION))
		{
			status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
			break;
		}

		verify_information = (PVERIFY_INFORMATION)Irp->AssociatedIrp.SystemBuffer;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = verify_information->Length;

		break;
	}

	case IOCTL_STORAGE_GET_DEVICE_NUMBER:
	{
		PSTORAGE_DEVICE_NUMBER number;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(STORAGE_DEVICE_NUMBER))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		number = (PSTORAGE_DEVICE_NUMBER)Irp->AssociatedIrp.SystemBuffer;

		number->DeviceType = device_extension->device_type;
		number->DeviceNumber = device_extension->device_number;
		number->PartitionNumber = (ULONG)-1;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(STORAGE_DEVICE_NUMBER);

		break;
	}

	case IOCTL_STORAGE_GET_HOTPLUG_INFO:
	{
		PSTORAGE_HOTPLUG_INFO info;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(STORAGE_HOTPLUG_INFO))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		info = (PSTORAGE_HOTPLUG_INFO)Irp->AssociatedIrp.SystemBuffer;

		info->Size = sizeof(STORAGE_HOTPLUG_INFO);
		info->MediaRemovable = 0;
		info->MediaHotplug = 0;
		info->DeviceHotplug = 0;
		info->WriteCacheEnableOverride = 0;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(STORAGE_HOTPLUG_INFO);

		break;
	}

	case IOCTL_VOLUME_GET_GPT_ATTRIBUTES:
	{
		PVOLUME_GET_GPT_ATTRIBUTES_INFORMATION attr;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(VOLUME_GET_GPT_ATTRIBUTES_INFORMATION))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		attr = (PVOLUME_GET_GPT_ATTRIBUTES_INFORMATION)Irp->AssociatedIrp.SystemBuffer;

		attr->GptAttributes = 0;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(VOLUME_GET_GPT_ATTRIBUTES_INFORMATION);

		break;
	}

	case IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS:
	{
		PVOLUME_DISK_EXTENTS ext;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(VOLUME_DISK_EXTENTS))
		{
			status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
			break;
		}
		/*
					// not needed since there is only one disk extent to return
					if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
						sizeof(VOLUME_DISK_EXTENTS) + ((NumberOfDiskExtents - 1) * sizeof(DISK_EXTENT)))
					{
						status = STATUS_BUFFER_OVERFLOW;
						Irp->IoStatus.Information = 0;
						break;
					}
		*/
		ext = (PVOLUME_DISK_EXTENTS)Irp->AssociatedIrp.SystemBuffer;

		ext->NumberOfDiskExtents = 1;
		ext->Extents[0].DiskNumber = device_extension->device_number;
		ext->Extents[0].StartingOffset.QuadPart = 0;
		ext->Extents[0].ExtentLength.QuadPart = device_extension->file_size.QuadPart;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(VOLUME_DISK_EXTENTS) /*+ ((NumberOfDiskExtents - 1) * sizeof(DISK_EXTENT))*/;

		break;
	}

#if (NTDDI_VERSION < NTDDI_VISTA)
#define IOCTL_DISK_IS_CLUSTERED CTL_CODE(IOCTL_DISK_BASE, 0x003e, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif  // NTDDI_VERSION < NTDDI_VISTA

	case IOCTL_DISK_IS_CLUSTERED:
	{
		PBOOLEAN clus;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(BOOLEAN))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		clus = (PBOOLEAN)Irp->AssociatedIrp.SystemBuffer;

		*clus = FALSE;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(BOOLEAN);

		break;
	}

	case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
	{
		PMOUNTDEV_NAME name;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(MOUNTDEV_NAME))
		{
			status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
			break;
		}

		name = (PMOUNTDEV_NAME)Irp->AssociatedIrp.SystemBuffer;
		name->NameLength = device_extension->device_name.Length * sizeof(WCHAR);

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			name->NameLength + sizeof(USHORT))
		{
			status = STATUS_BUFFER_OVERFLOW;
			Irp->IoStatus.Information = sizeof(MOUNTDEV_NAME);
			break;
		}

		RtlCopyMemory(name->Name, device_extension->device_name.Buffer, name->NameLength);

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = name->NameLength + sizeof(USHORT);

		break;
	}

	case IOCTL_CDROM_READ_TOC_EX:
	{
		KdPrint(("ThawSpace: Unhandled ioctl IOCTL_CDROM_READ_TOC_EX.\n"));
		status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		break;
	}
	case IOCTL_DISK_GET_MEDIA_TYPES:
	{
		KdPrint(("ThawSpace: Unhandled ioctl IOCTL_DISK_GET_MEDIA_TYPES.\n"));
		status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		break;
	}
	case 0x66001b:
	{
		KdPrint(("ThawSpace: Unhandled ioctl FT_BALANCED_READ_MODE.\n"));
		status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		break;
	}
	case IOCTL_SCSI_GET_CAPABILITIES:
	{
		KdPrint(("ThawSpace: Unhandled ioctl IOCTL_SCSI_GET_CAPABILITIES.\n"));
		status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		break;
	}
	case IOCTL_SCSI_PASS_THROUGH:
	{
		KdPrint(("ThawSpace: Unhandled ioctl IOCTL_SCSI_PASS_THROUGH.\n"));
		status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		break;
	}
	case IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES:
	{
		KdPrint(("ThawSpace: Unhandled ioctl IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES.\n"));
		status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		break;
	}
	case IOCTL_STORAGE_QUERY_PROPERTY:
	{
		KdPrint(("ThawSpace: Unhandled ioctl IOCTL_STORAGE_QUERY_PROPERTY.\n"));
		status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		break;
	}

#if (NTDDI_VERSION < NTDDI_VISTA)
#define IOCTL_VOLUME_QUERY_ALLOCATION_HINT CTL_CODE(IOCTL_VOLUME_BASE, 20, METHOD_OUT_DIRECT, FILE_READ_ACCESS)
#endif  // NTDDI_VERSION < NTDDI_VISTA

	case IOCTL_VOLUME_QUERY_ALLOCATION_HINT:
	{
		KdPrint(("ThawSpace: Unhandled ioctl IOCTL_VOLUME_QUERY_ALLOCATION_HINT.\n"));
		status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		break;
	}
	default:
	{
		KdPrint((
			"ThawSpace: Unknown IoControlCode %#x\n",
			io_stack->Parameters.DeviceIoControl.IoControlCode
			));

		status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
	}
	}

	if (status != STATUS_PENDING)
	{
		Irp->IoStatus.Status = status;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}

	return status;
}

#pragma code_seg("PAGE")

VOID
ThawSpaceThread(
	IN PVOID Context
)
{
	PDEVICE_OBJECT      device_object;
	PDEVICE_EXTENSION   device_extension;
	PLIST_ENTRY         request;
	PIRP                irp;
	PIO_STACK_LOCATION  io_stack;
	PUCHAR              system_buffer;
	PUCHAR              buffer;

	PAGED_CODE();

	ASSERT(Context != NULL);

	device_object = (PDEVICE_OBJECT)Context;

	device_extension = (PDEVICE_EXTENSION)device_object->DeviceExtension;

	KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

	ThawSpaceAdjustPrivilege(SE_IMPERSONATE_PRIVILEGE, TRUE);

	for (;;)
	{
		KeWaitForSingleObject(
			&device_extension->request_event,
			Executive,
			KernelMode,
			FALSE,
			NULL
		);

		if (device_extension->terminate_thread)
		{
			PsTerminateSystemThread(STATUS_SUCCESS);
		}

		while ((request = ExInterlockedRemoveHeadList(
			&device_extension->list_head,
			&device_extension->list_lock
		)) != NULL)
		{
			irp = CONTAINING_RECORD(request, IRP, Tail.Overlay.ListEntry);

			io_stack = IoGetCurrentIrpStackLocation(irp);

			switch (io_stack->MajorFunction)
			{
			case IRP_MJ_READ:
				system_buffer = (PUCHAR)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
				if (system_buffer == NULL)
				{
					irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					irp->IoStatus.Information = 0;
					break;
				}
				buffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, io_stack->Parameters.Read.Length, POOL_TAG);
				if (buffer == NULL)
				{
					irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					irp->IoStatus.Information = 0;
					break;
				}
				ZwReadFile(
					device_extension->file_handle,
					NULL,
					NULL,
					NULL,
					&irp->IoStatus,
					buffer,
					io_stack->Parameters.Read.Length,
					&io_stack->Parameters.Read.ByteOffset,
					NULL
				);
				RtlCopyMemory(system_buffer, buffer, io_stack->Parameters.Read.Length);
				ExFreePool(buffer);
				break;

			case IRP_MJ_WRITE:
				if ((io_stack->Parameters.Write.ByteOffset.QuadPart +
					io_stack->Parameters.Write.Length) >
					device_extension->file_size.QuadPart)
				{
					irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
					irp->IoStatus.Information = 0;
					break;
				}
				ZwWriteFile(
					device_extension->file_handle,
					NULL,
					NULL,
					NULL,
					&irp->IoStatus,
					MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority),
					io_stack->Parameters.Write.Length,
					&io_stack->Parameters.Write.ByteOffset,
					NULL
				);
				break;

			case IRP_MJ_DEVICE_CONTROL:
				switch (io_stack->Parameters.DeviceIoControl.IoControlCode)
				{
				case IOCTL_THAWSPACE_OPEN_FILE:

					SeImpersonateClient(device_extension->security_client_context, NULL);

					irp->IoStatus.Status = ThawSpaceOpenFile(device_object, irp->AssociatedIrp.SystemBuffer);

					PsRevertToSelf();

					break;

				case IOCTL_THAWSPACE_CLOSE_FILE:
					irp->IoStatus.Status = ThawSpaceCloseFile(device_object);
					break;

				default:
					irp->IoStatus.Status = STATUS_DRIVER_INTERNAL_ERROR;
				}
				break;

			default:
				irp->IoStatus.Status = STATUS_DRIVER_INTERNAL_ERROR;
			}

			IoCompleteRequest(
				irp,
				(CCHAR)(NT_SUCCESS(irp->IoStatus.Status) ?
					IO_DISK_INCREMENT : IO_NO_INCREMENT)
			);
		}
	}
}

NTSTATUS
ThawSpaceOpenFile(
	IN PDEVICE_OBJECT            DeviceObject,
	IN POPEN_FILE_INFORMATION    open_file_information
)
{
	PDEVICE_EXTENSION               device_extension;
	NTSTATUS                        status;
	OBJECT_ATTRIBUTES               object_attributes;
	FILE_END_OF_FILE_INFORMATION    file_eof;
	FILE_BASIC_INFORMATION          file_basic;
	FILE_STANDARD_INFORMATION       file_standard;
	FILE_ALIGNMENT_INFORMATION      file_alignment;
	IO_STATUS_BLOCK                 io_status;
	WCHAR                           sym_link_name[256];
	UNICODE_STRING                  sym_link;

	PAGED_CODE();

	ASSERT(DeviceObject != NULL);
	ASSERT(open_file_information != NULL);

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	device_extension->read_only = open_file_information->ReadOnly;

	device_extension->file_name.Length = open_file_information->FileNameLength * sizeof(WCHAR);
	device_extension->file_name.MaximumLength = open_file_information->FileNameLength * sizeof(WCHAR);
	device_extension->file_name.Buffer = ExAllocatePoolWithTag(NonPagedPool, open_file_information->FileNameLength * sizeof(WCHAR), POOL_TAG);

	if (device_extension->file_name.Buffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlCopyMemory(
		device_extension->file_name.Buffer,
		open_file_information->FileName,
		open_file_information->FileNameLength * sizeof(WCHAR)
	);

	InitializeObjectAttributes(
		&object_attributes,
		&device_extension->file_name,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);

	status = ZwCreateFile(
		&device_extension->file_handle,
		device_extension->read_only ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE,
		&object_attributes,
		&io_status,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		device_extension->read_only ? FILE_SHARE_READ : 0,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE |
		FILE_RANDOM_ACCESS |
		FILE_NO_INTERMEDIATE_BUFFERING |
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
	);

	if (NT_SUCCESS(status))
	{
		KdPrint(("ThawSpace: File %wZ opened.\n", device_extension->file_name));
	}

	if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_NO_SUCH_FILE)
	{
		if (device_extension->read_only || open_file_information->FileSize.QuadPart == 0)
		{
			DbgPrint("ThawSpace: File %wZ not found.\n", device_extension->file_name);
			ExFreePool(device_extension->file_name.Buffer);
			return STATUS_NO_SUCH_FILE;
		}
		else
		{
			status = ZwCreateFile(
				&device_extension->file_handle,
				GENERIC_READ | GENERIC_WRITE,
				&object_attributes,
				&io_status,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				0,
				FILE_OPEN_IF,
				FILE_NON_DIRECTORY_FILE |
				FILE_RANDOM_ACCESS |
				FILE_NO_INTERMEDIATE_BUFFERING |
				FILE_SYNCHRONOUS_IO_NONALERT,
				NULL,
				0
			);

			if (!NT_SUCCESS(status))
			{
				DbgPrint("ThawSpace: File %wZ could not be created.\n", device_extension->file_name);
				ExFreePool(device_extension->file_name.Buffer);
				return status;
			}

			if (io_status.Information == FILE_CREATED)
			{
				KdPrint(("ThawSpace: File %wZ created.\n", device_extension->file_name));
				status = ZwFsControlFile(
					device_extension->file_handle,
					NULL,
					NULL,
					NULL,
					&io_status,
					FSCTL_SET_SPARSE,
					NULL,
					0,
					NULL,
					0
				);

				if (NT_SUCCESS(status))
				{
					KdPrint(("ThawSpace: File attributes set to sparse.\n"));
				}

				file_eof.EndOfFile.QuadPart = open_file_information->FileSize.QuadPart;

				status = ZwSetInformationFile(
					device_extension->file_handle,
					&io_status,
					&file_eof,
					sizeof(FILE_END_OF_FILE_INFORMATION),
					FileEndOfFileInformation
				);

				if (!NT_SUCCESS(status))
				{
					DbgPrint("ThawSpace: eof could not be set.\n");
					ExFreePool(device_extension->file_name.Buffer);
					ZwClose(device_extension->file_handle);
					return status;
				}
				KdPrint(("ThawSpace: eof set to %I64u.\n", file_eof.EndOfFile.QuadPart));
			}
		}
	}
	else if (!NT_SUCCESS(status))
	{
		DbgPrint("ThawSpace: File %wZ could not be opened.\n", device_extension->file_name);
		ExFreePool(device_extension->file_name.Buffer);
		return status;
	}

	status = ZwQueryInformationFile(
		device_extension->file_handle,
		&io_status,
		&file_basic,
		sizeof(FILE_BASIC_INFORMATION),
		FileBasicInformation
	);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(device_extension->file_name.Buffer);
		ZwClose(device_extension->file_handle);
		return status;
	}

	//
	// The NT cache manager can deadlock if a filesystem that is using the cache
	// manager is used in a virtual disk that stores its file on a filesystem
	// that is also using the cache manager, this is why we open the file with
	// FILE_NO_INTERMEDIATE_BUFFERING above, however if the file is compressed
	// or encrypted NT will not honor this request and cache it anyway since it
	// need to store the decompressed/unencrypted data somewhere, therefor we put
	// an extra check here and don't alow disk images to be compressed/encrypted.
	//
	if (file_basic.FileAttributes & (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED))
	{
		DbgPrint("ThawSpace: Warning: File is compressed or encrypted. File attributes: %#x.\n", file_basic.FileAttributes);
		/*
				ExFreePool(device_extension->file_name.Buffer);
				ZwClose(device_extension->file_handle);
				Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
				Irp->IoStatus.Information = 0;
				return STATUS_ACCESS_DENIED;
		*/
	}

	status = ZwQueryInformationFile(
		device_extension->file_handle,
		&io_status,
		&file_standard,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation
	);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(device_extension->file_name.Buffer);
		ZwClose(device_extension->file_handle);
		return status;
	}

	device_extension->file_size.QuadPart = file_standard.EndOfFile.QuadPart;

	status = ZwQueryInformationFile(
		device_extension->file_handle,
		&io_status,
		&file_alignment,
		sizeof(FILE_ALIGNMENT_INFORMATION),
		FileAlignmentInformation
	);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(device_extension->file_name.Buffer);
		ZwClose(device_extension->file_handle);
		return status;
	}

	DeviceObject->AlignmentRequirement = file_alignment.AlignmentRequirement;

	if (device_extension->read_only)
	{
		DeviceObject->Characteristics |= FILE_READ_ONLY_DEVICE;
	}
	else
	{
		DeviceObject->Characteristics &= ~FILE_READ_ONLY_DEVICE;
	}

	device_extension->media_in_device = TRUE;

	device_extension->drive_letter = open_file_information->DriveLetter;

	swprintf_s(sym_link_name, 256, L"\\??\\%c:", device_extension->drive_letter);
	RtlInitUnicodeString(&sym_link, sym_link_name);
	IoCreateSymbolicLink(&sym_link, &device_extension->device_name);
	DbgPrint("ThawSpace: Symbolic link %wZ -> %wZ\n", device_extension->device_name, sym_link);

	DbgPrint("ThawSpace: File %wZ mount on %c: ok.\n", device_extension->file_name, device_extension->drive_letter);

	return STATUS_SUCCESS;
}

NTSTATUS
ThawSpaceCloseFile(
	IN PDEVICE_OBJECT   DeviceObject
)
{
	PDEVICE_EXTENSION device_extension;
	WCHAR             sym_link_name[256];
	UNICODE_STRING    sym_link;

	PAGED_CODE();

	ASSERT(DeviceObject != NULL);

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	if (device_extension->media_in_device)
	{
		ExFreePool(device_extension->file_name.Buffer);

		ZwClose(device_extension->file_handle);

		device_extension->media_in_device = FALSE;

		swprintf_s(sym_link_name, 256, L"\\??\\%c:", device_extension->drive_letter);
		RtlInitUnicodeString(&sym_link, sym_link_name);
		IoDeleteSymbolicLink(&sym_link);

		DbgPrint("ThawSpace: Unmount %c: ok.\n", device_extension->drive_letter);
	}

	return STATUS_SUCCESS;
}

NTSTATUS
ThawSpaceAdjustPrivilege(
	IN ULONG    Privilege,
	IN BOOLEAN  Enable
)
{
	NTSTATUS            status;
	HANDLE              token_handle;
	TOKEN_PRIVILEGES    token_privileges;

	PAGED_CODE();

	status = ZwOpenProcessToken(
		NtCurrentProcess(),
		TOKEN_ALL_ACCESS,
		&token_handle
	);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	token_privileges.PrivilegeCount = 1;
	token_privileges.Privileges[0].Luid = RtlConvertUlongToLuid(Privilege);
	token_privileges.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;

	status = ZwAdjustPrivilegesToken(
		token_handle,
		FALSE,
		&token_privileges,
		sizeof(token_privileges),
		NULL,
		NULL
	);

	ZwClose(token_handle);

	return status;
}

#pragma code_seg() // end "PAGE"
