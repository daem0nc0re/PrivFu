#include <ntifs.h>

#define DRIVER_PREFIX "PrivManDrv: "
#define DEVICE_PATH L"\\Device\\PrivMan"
#define SYMLINK_PATH L"\\??\\PrivMan"
#define PRIVILEGES_OFFSET 0x40

//
// IOCTL Code Definitions
//
#define IOCTL_GET_TOKEN_PRIVILEGES CTL_CODE(0x8000, 0x0000, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_TOKEN_PRIVILEGES CTL_CODE(0x8000, 0x0001, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Windows Definitions
//
typedef struct _SEP_TOKEN_PRIVILEGES
{
	ULONGLONG Present;
	ULONGLONG Enabled;
	ULONGLONG EnabledByDefault;
} SEP_TOKEN_PRIVILEGES, * PSEP_TOKEN_PRIVILEGES;

//
// IOCTL Structures
//
typedef struct _IOCTL_GET_TOKEN_PRIVILEGES_INPUT
{
	HANDLE UniqueProcess;
} IOCTL_GET_TOKEN_PRIVILEGES_INPUT, * PIOCTL_GET_TOKEN_PRIVILEGES_INPUT;

typedef struct _IOCTL_GET_TOKEN_PRIVILEGES_OUTPUT
{
	HANDLE UniqueProcess;
	SEP_TOKEN_PRIVILEGES Privileges;
} IOCTL_GET_TOKEN_PRIVILEGES_OUTPUT, * PIOCTL_GET_TOKEN_PRIVILEGES_OUTPUT;

typedef struct _IOCTL_SET_TOKEN_PRIVILEGES_INPUT
{
	HANDLE UniqueProcess;
	SEP_TOKEN_PRIVILEGES Privileges;
} IOCTL_SET_TOKEN_PRIVILEGES_INPUT, * PIOCTL_SET_TOKEN_PRIVILEGES_INPUT;


//
// Prototypes
//
void DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS OnCreateClose(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp);
NTSTATUS OnDeviceControl(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp);
NTSTATUS GetTokenPrivieleges(
	_In_ HANDLE UniqueProcess,
	_In_ PSEP_TOKEN_PRIVILEGES Privileges);
NTSTATUS SetTokenPrivieleges(
	_In_ HANDLE UniqueProcess,
	_In_ PSEP_TOKEN_PRIVILEGES Privileges);


extern "C"
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS ntstatus = STATUS_FAILED_DRIVER_ENTRY;
	PDEVICE_OBJECT pDeviceObject = nullptr;

	do
	{
		UNICODE_STRING devicePath = RTL_CONSTANT_STRING(DEVICE_PATH);
		UNICODE_STRING symlinkPath = RTL_CONSTANT_STRING(SYMLINK_PATH);

		ntstatus = ::IoCreateDevice(
			DriverObject,
			NULL,
			&devicePath,
			FILE_DEVICE_UNKNOWN,
			NULL,
			FALSE,
			&pDeviceObject);

		if (!NT_SUCCESS(ntstatus))
		{
			pDeviceObject = nullptr;
			KdPrint((DRIVER_PREFIX "Failed to create device (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}

		ntstatus = ::IoCreateSymbolicLink(&symlinkPath, &devicePath);

		if (!NT_SUCCESS(ntstatus))
		{
			KdPrint((DRIVER_PREFIX "Failed to create symbolic link (NTSTATUS = 0x%08X).\n", ntstatus));
			break;
		}

		DriverObject->DriverUnload = DriverUnload;
		DriverObject->MajorFunction[IRP_MJ_CREATE] = OnCreateClose;
		DriverObject->MajorFunction[IRP_MJ_CLOSE] = OnCreateClose;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnDeviceControl;

		KdPrint((DRIVER_PREFIX "Driver is loaded successfully.\n"));
	} while (false);

	if (!NT_SUCCESS(ntstatus) && (pDeviceObject != nullptr))
		::IoDeleteDevice(pDeviceObject);

	return ntstatus;
}


void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symlinkPath = RTL_CONSTANT_STRING(SYMLINK_PATH);
	::IoDeleteSymbolicLink(&symlinkPath);
	::IoDeleteDevice(DriverObject->DeviceObject);

	KdPrint((DRIVER_PREFIX "Driver is unloaded.\n"));
}


//
// Major Functions
//
NTSTATUS OnCreateClose(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS ntstatus = STATUS_SUCCESS;
	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = 0u;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}


NTSTATUS OnDeviceControl(
	_Inout_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS ntstatus = STATUS_INVALID_DEVICE_REQUEST;
	ULONG_PTR info = NULL;
	PIO_STACK_LOCATION irpSp = ::IoGetCurrentIrpStackLocation(Irp);
	auto& dic = irpSp->Parameters.DeviceIoControl;

	switch (dic.IoControlCode)
	{
	case IOCTL_GET_TOKEN_PRIVILEGES:
	{
		if (dic.InputBufferLength < sizeof(IOCTL_GET_TOKEN_PRIVILEGES_INPUT))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Input buffer is too small.\n"));
			break;
		}
		else if (dic.OutputBufferLength < sizeof(IOCTL_GET_TOKEN_PRIVILEGES_OUTPUT))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Output buffer is too small.\n"));
			break;
		}

		auto pInOutBuffer = (PIOCTL_GET_TOKEN_PRIVILEGES_INPUT)Irp->AssociatedIrp.SystemBuffer;
		auto pTokenPrivleges = &((PIOCTL_GET_TOKEN_PRIVILEGES_OUTPUT)pInOutBuffer)->Privileges;
		ntstatus = ::GetTokenPrivieleges(pInOutBuffer->UniqueProcess, pTokenPrivleges);

		if (NT_SUCCESS(ntstatus))
		{
			info = sizeof(IOCTL_GET_TOKEN_PRIVILEGES_OUTPUT);
			KdPrint((DRIVER_PREFIX "Got token privileges.\n"));
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Failed to get token privileges (NTSTATUS = 0x%08X).\n", ntstatus));
		}

		break;
	}
	case IOCTL_SET_TOKEN_PRIVILEGES:
	{
		if (dic.InputBufferLength < sizeof(IOCTL_SET_TOKEN_PRIVILEGES_INPUT))
		{
			ntstatus = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Input buffer is too small.\n"));
			break;
		}

		auto pInputBuffer = (PIOCTL_SET_TOKEN_PRIVILEGES_INPUT)Irp->AssociatedIrp.SystemBuffer;
		auto pTokenPrivleges = &pInputBuffer->Privileges;
		ntstatus = ::SetTokenPrivieleges(pInputBuffer->UniqueProcess, pTokenPrivleges);

		if (NT_SUCCESS(ntstatus))
		{
			info = sizeof(IOCTL_SET_TOKEN_PRIVILEGES_INPUT);
			KdPrint((DRIVER_PREFIX "Token privileges are set successfully.\n"));
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Failed to set token privileges (NTSTATUS = 0x%08X).\n", ntstatus));
		}

		break;
	}
	default:
	{
		KdPrint((DRIVER_PREFIX "Invalid IOCTL code (0x%08X).\n", dic.IoControlCode));
		break;
	}
	}

	Irp->IoStatus.Status = ntstatus;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);

	return ntstatus;
}


//
// IOCTL Routine
//
NTSTATUS GetTokenPrivieleges(
	_In_ HANDLE UniqueProcess,
	_In_ PSEP_TOKEN_PRIVILEGES Privileges)
{
	PEPROCESS pEprocess = nullptr;
	NTSTATUS ntstatus = ::PsLookupProcessByProcessId(UniqueProcess, &pEprocess);

	if (NT_SUCCESS(ntstatus))
	{
		PACCESS_TOKEN pPrimaryToken = ::PsReferencePrimaryToken(pEprocess);
		auto pTokenPrivileges = (PSEP_TOKEN_PRIVILEGES)((ULONG_PTR)pPrimaryToken + PRIVILEGES_OFFSET);
		Privileges->Present = pTokenPrivileges->Present;
		Privileges->Enabled = pTokenPrivileges->Enabled;
		Privileges->EnabledByDefault = pTokenPrivileges->EnabledByDefault;
		::PsDereferencePrimaryToken(pPrimaryToken);
		ObDereferenceObject(pEprocess);
	}

	return ntstatus;
}


NTSTATUS SetTokenPrivieleges(
	_In_ HANDLE UniqueProcess,
	_In_ PSEP_TOKEN_PRIVILEGES Privileges)
{
	PEPROCESS pEprocess = nullptr;
	NTSTATUS ntstatus = ::PsLookupProcessByProcessId(UniqueProcess, &pEprocess);

	if (NT_SUCCESS(ntstatus))
	{
		PACCESS_TOKEN pPrimaryToken = ::PsReferencePrimaryToken(pEprocess);
		auto pTokenPrivileges = (PSEP_TOKEN_PRIVILEGES)((ULONG_PTR)pPrimaryToken + PRIVILEGES_OFFSET);
		pTokenPrivileges->Present = Privileges->Present;
		pTokenPrivileges->Enabled = Privileges->Enabled;
		pTokenPrivileges->EnabledByDefault = Privileges->EnabledByDefault;
		::PsDereferencePrimaryToken(pPrimaryToken);
		ObDereferenceObject(pEprocess);
	}

	return ntstatus;
}