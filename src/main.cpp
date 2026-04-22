#include <ntifs.h>
#include <ntddk.h>
#include <fltkernel.h>
#include "ioctlPidCommand.h"
#include "Notifications.h"

// Global context and variables
PFLT_FILTER g_FilterHandle = NULL;
LARGE_INTEGER g_RegCookie;

// Addning global variables for objects
PDEVICE_OBJECT g_DeviceObject = NULL;
UNICODE_STRING devName;
UNICODE_STRING symLink;


const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreFileOperation, PostFileOperation },
    { IRP_MJ_READ, 0, PreFileOperation, PostFileOperation},
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL, Callbacks,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    
    NTSTATUS status;

    KeInitializeSpinLock(&g_PidLock);

    // Initing internal device name and symbolic link for User-mode
    RtlInitUnicodeString(&devName, L"\\Device\\SysMon_A8F9_B2C4");
    RtlInitUnicodeString(&symLink, L"\\DosDevices\\SysMon_A8F9_B2C4");

    // Creating device
    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[main] Failed to create device. Status: 0x%X\n", status);
        return status;
    }

    // Creating symbolic link \\.\SysMon_A8F9_B2C4
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[main] Failed to create symbolic link. Status: 0x%X\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlHandler;

    InitializeSharedMemory();


    // Setting notify for threads
    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);
    if (!NT_SUCCESS(status)) DbgPrint("[main] Failed to set thread notify routine. [-]\n");

    // Setting notify for register
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"385201"); // Setting unique height
    status = CmRegisterCallbackEx(RegistryCallback, &altitude, DriverObject, NULL, &g_RegCookie, NULL);
    if (!NT_SUCCESS(status)) DbgPrint("[main] Failed to register registry callback.[-]\n");

    // Setting notify for files
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle);
    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(g_FilterHandle);
    }
    else {
        DbgPrint("[main] Failed to register minifilter. [-]\n");
    }

    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[main] Failed to register process notify callback.\n");
    }

    DbgPrint("[+] Custom pro*mon loaded. [+]\n");
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
    CmUnRegisterCallback(g_RegCookie);
    FltUnregisterFilter(g_FilterHandle);
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);
    FreeSharedMemory();
    DbgPrint("[+] Monitor unloaded safely. [+]\n");
}