#include <ntifs.h>
#include <ntddk.h>
#include <fltkernel.h>
#include "ioctlPidCommand.h"

// --- Глобальные контексты и дескрипторы ---
PFLT_FILTER g_FilterHandle = NULL;
LARGE_INTEGER g_RegCookie;

// Добавляем глобальные переменные для устройства
PDEVICE_OBJECT g_DeviceObject = NULL;
UNICODE_STRING devName;
UNICODE_STRING symLink;

// --- 1. Мониторинг потоков (Threads) ---
VOID ThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
    if (Create) {
        DbgPrint("[THREAD] Created: PID %p, TID %p\n", ProcessId, ThreadId);
    }
    else {
        DbgPrint("[THREAD] Terminated: PID %p, TID %p\n", ProcessId, ThreadId);
    }
}

// --- 2. Мониторинг реестра (Registry) ---
NTSTATUS RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2) {
    UNREFERENCED_PARAMETER(CallbackContext);

    REG_NOTIFY_CLASS Operation = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    switch (Operation) {
    case RegNtPreCreateKeyEx: {
        PREG_CREATE_KEY_INFORMATION Info = (PREG_CREATE_KEY_INFORMATION)Argument2;
        DbgPrint("[REGISTRY] Create value: %wZ\n", Info->CompleteName);
        break;
    }
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION Info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        DbgPrint("[REGISTRY] Set value: %wZ\n", Info->ValueName);
        break;
    }
    case RegNtPreQueryValueKey: {
        PREG_QUERY_VALUE_KEY_INFORMATION Info = (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2;
        DbgPrint("[REGISTRY] Get Value: %wZ\n", Info->ValueName);
        break;
    }

    }
    return STATUS_SUCCESS;
}

// --- 3. Мониторинг файлов (Minifilter) ---
FLT_PREOP_CALLBACK_STATUS PreFileOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;

        PFLT_FILE_NAME_INFORMATION nameInfo;
        if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
            DbgPrint("[FILE] Wants to: ");
            switch (createDisposition) {
                case FILE_CREATE:
                    DbgPrint("Create New: %wZ\n", &nameInfo->Name);
                    break;
                case FILE_OPEN:
                case FILE_OPEN_IF:
                    DbgPrint("Open Existing: %wZ\n", &nameInfo->Name);
                    break;
                case FILE_OVERWRITE:
                case FILE_OVERWRITE_IF:
                case FILE_SUPERSEDE:
                    DbgPrint("Overwrite: %wZ\n", &nameInfo->Name);
                    break;
                default:
                    DbgPrint(" [-] Unknown operation [-]");
                    break;
            }
            FltReleaseFileNameInformation(nameInfo);
        }
    }

    if (Data->Iopb->MajorFunction == IRP_MJ_READ) {
        PFLT_FILE_NAME_INFORMATION nameInfo;
        if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
            DbgPrint("[FILE] Read: %wZ\n", &nameInfo->Name);
            FltReleaseFileNameInformation(nameInfo);
        }

    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreFileOperation, NULL },
    { IRP_MJ_READ, 0, PreFileOperation, NULL},
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL, Callbacks,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

// --- Точка входа в драйвер ---
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    
    NTSTATUS status;

    // 1. Создаем внутреннее имя устройства и символьную ссылку для User-Mode
    RtlInitUnicodeString(&devName, L"\\Device\\SysMon_A8F9_B2C4");
    RtlInitUnicodeString(&symLink, L"\\DosDevices\\SysMon_A8F9_B2C4");

    // 2. Создаем само устройство
    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to create device. Status: 0x%X\n", status);
        return status;
    }

    // 3. Создаем символьную ссылку (именно она позволяет использовать \\.\SysMon_A8F9_B2C4 в User-Mode)
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to create symbolic link. Status: 0x%X\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlHandler;

    // 1. Потоки
    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);
    if (!NT_SUCCESS(status)) DbgPrint("[-] Failed to set thread notify routine. [-]\n");

    // 2. Реестр
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"385201"); // Уникальная высота
    status = CmRegisterCallbackEx(RegistryCallback, &altitude, DriverObject, NULL, &g_RegCookie, NULL);
    if (!NT_SUCCESS(status)) DbgPrint("[-] Failed to register registry callback.[-]\n");

    // 3. Файлы (Минифильтр)
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle);
    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(g_FilterHandle);
    }
    else {
        DbgPrint("[-] Failed to register minifilter. [-]\n");
    }

    DbgPrint("[+] Custom pro*mon loaded. [+]\n");
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);
    CmUnRegisterCallback(g_RegCookie);
    FltUnregisterFilter(g_FilterHandle);
    // ВАЖНО: Удаляем символьную ссылку и устройство при выгрузке, иначе они "зависнут" в системе
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);
    DbgPrint("[+] Monitor unloaded safely. [+]\n");
}