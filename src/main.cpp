#include <ntifs.h>
#include <ntddk.h>
#include <fltkernel.h>
#include "ioctlPidCommand.h"
#include "Notifications.h"
#include <ntstrsafe.h>


#define SYMLINK_FILE_PATH L"\\??\\C:\\sysmon_link.txt"


// Global context and variables
PFLT_FILTER g_FilterHandle = NULL;
LARGE_INTEGER g_RegCookie;

// Addning global variables for objects
PDEVICE_OBJECT g_DeviceObject = NULL;
WCHAR g_DevNameBuffer[128] = { 0 };
WCHAR g_SymLinkBuffer[128] = { 0 };
UNICODE_STRING devName;
UNICODE_STRING symLink;


const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreFileOperation, PostFileOperation },
    { IRP_MJ_READ, 0, PreFileOperation, PostFileOperation},
    { IRP_MJ_WRITE, 0, PreFileOperation, PostFileOperation},
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL, Callbacks,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};


NTSTATUS CreateRandomSymlinkDeviceLink(PDRIVER_OBJECT DriverObject) {
    NTSTATUS status;
    LARGE_INTEGER sysTime;
    KeQuerySystemTime(&sysTime);
    ULONG seed = sysTime.LowPart;
    ULONG randomPart1 = RtlRandomEx(&seed);
    ULONG randomPart2 = RtlRandomEx(&seed);

    RtlStringCbPrintfW(g_DevNameBuffer, sizeof(g_DevNameBuffer), L"\\Device\\SysMon_%08X_%08X", randomPart1, randomPart2);
    RtlStringCbPrintfW(g_SymLinkBuffer, sizeof(g_SymLinkBuffer), L"\\DosDevices\\SysMon_%08X_%08X", randomPart1, randomPart2);

    RtlInitUnicodeString(&devName, g_DevNameBuffer);
    RtlInitUnicodeString(&symLink, g_SymLinkBuffer);

    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to create random device. Status: 0x%X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to create random symbolic link. Status: 0x%X\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    UNICODE_STRING filePath;
    RtlInitUnicodeString(&filePath, SYMLINK_FILE_PATH);
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hFile;
    IO_STATUS_BLOCK ioStatusBlock;

    // Creating or overwriting the file
    status = ZwCreateFile(&hFile, GENERIC_WRITE, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL,
        0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (NT_SUCCESS(status)) {
        WCHAR userLinkBuffer[128];
        RtlStringCbPrintfW(userLinkBuffer, sizeof(userLinkBuffer), L"\\\\.\\SysMon_%08X_%08X", randomPart1, randomPart2);

        ULONG bytesToWrite = (ULONG)(wcslen(userLinkBuffer) * sizeof(WCHAR));
        ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatusBlock, userLinkBuffer, bytesToWrite, NULL, NULL);
        ZwClose(hFile);
        DbgPrint("[+] Symlink saved to C:\\sysmon_link.txt\n");
    }
    else {
        DbgPrint("[-] Failed to write symlink file to C:\\. Status: 0x%X\n", status);
        DbgPrint("[?] Current symlink: %wZ", &symLink);
    }
    return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {

    PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);

    if (g_RegCookie.QuadPart != 0) {
        CmUnRegisterCallback(g_RegCookie);
    }

    if (g_FilterHandle != NULL) {
        FltUnregisterFilter(g_FilterHandle);
    }

    FreeSharedMemory();

    IoDeleteSymbolicLink(&symLink);
    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
    DbgPrint("[+] Monitor unloaded safely. [+]\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    
    NTSTATUS status = 0;

    KeInitializeSpinLock(&g_PidLock);
    status = CreateRandomSymlinkDeviceLink(DriverObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlHandler;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = CreateCloseHandler;

    InitializeSharedMemory();


    // Setting notify for threads
    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);
    if (!NT_SUCCESS(status)) DbgPrint("[DriverEntry] Failed to set thread notify routine. [-]\n");

    // Setting notify for register
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"385201"); // Setting unique height
    status = CmRegisterCallbackEx(RegistryCallback, &altitude, DriverObject, NULL, &g_RegCookie, NULL);
    if (!NT_SUCCESS(status)) DbgPrint("[DriverEntry] Failed to register registry callback.[-]\n");

    // Setting notify for files
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle);
    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(g_FilterHandle);
    }
    else {
        DbgPrint("[DriverEntry] Failed to register minifilter. [-]\n");
    }

    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DriverEntry] Failed to register process notify callback.\n");
    }

    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("[+] Custom pro*mon loaded. [+]\n");
    return STATUS_SUCCESS;
}