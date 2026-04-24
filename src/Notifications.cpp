#include <ntifs.h>
#include <fltkernel.h>
#include "Notifications.h"
#include "ioctlPidCommand.h"

ULONG g_TrackedPIDs[MAX_TRACKED_PIDS] = { 0 };
ULONG g_TrackedPIDCount = 0;
KSPIN_LOCK g_PidLock;

BOOLEAN isPidTracked(ULONG Pid) {
    if (Pid == 0 || g_TrackedPIDCount == 0) return FALSE;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_PidLock, &oldIrql);
    BOOLEAN found = FALSE;
    for (ULONG i = 0; i < MAX_TRACKED_PIDS; ++i) {
        if (g_TrackedPIDs[i] == Pid) { found = TRUE; break; }
    }
    KeReleaseSpinLock(&g_PidLock, oldIrql);
    return found;
}

VOID AddTrackedPid(ULONG Pid) {
    if (isPidTracked(Pid)) { return; }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_PidLock, &oldIrql);

    BOOLEAN added = FALSE;
    for (ULONG i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (g_TrackedPIDs[i] == 0) {
            g_TrackedPIDs[i] = Pid;
            g_TrackedPIDCount++;
            added = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_PidLock, oldIrql);

    if (!added) {
        LogToSharedBuffer(L"[AddTrackedPid] Tracked PIDs array is full. Cannot add PID: %d\n", Pid);
    }
}

VOID RemoveTrackedPid(ULONG Pid) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_PidLock, &oldIrql);

    for (ULONG i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (g_TrackedPIDs[i] == Pid) {
            g_TrackedPIDs[i] = 0;
            g_TrackedPIDCount--;
            break;
        }
    }

    KeReleaseSpinLock(&g_PidLock, oldIrql);
}

VOID ProcessNotifyCallbackEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);
    ULONG currentPid = (ULONG)(ULONG_PTR)ProcessId;
    

    if (CreateInfo == NULL) {
        if (isPidTracked(currentPid)) {
            RemoveTrackedPid(currentPid);
            LogToSharedBuffer(L"[PROCESS] Tracked process terminated, removed from list. PID: %d\n", currentPid);
        }
        return;
    }

    ULONG parentPid = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;
    

    if (isPidTracked(parentPid)) {
        AddTrackedPid(currentPid);

        LogToSharedBuffer(L"[PROCESS] Child process %wZ (PID: %d) inherit tracking.\n", CreateInfo->ImageFileName, currentPid);
        if (CreateInfo->CommandLine != NULL) {
            LogToSharedBuffer(L"[PROCESS] launch arguments: %wZ\n", CreateInfo->CommandLine);
            //ULONG lenght = min(CreateInfo->ImageFileName->Length, sizeof(processEvent.Data.Process.ImageName) - sizeof(WCHAR));
            //RtlCopyMemory(processEvent.Data.Process.ImageName, CreateInfo->ImageFileName->Buffer, lenght)
        } else {
            LogToSharedBuffer(L"[PROCESS] launch arguments: None\n");
        }
        return;
    }

    if (CreateInfo->ImageFileName != NULL && g_TargetProcessName[0] != L'\0') {
        UNICODE_STRING targetNameU;
        RtlInitUnicodeString(&targetNameU, g_TargetProcessName);

        if (RtlSuffixUnicodeString(&targetNameU, CreateInfo->ImageFileName, TRUE)) {
            AddTrackedPid(currentPid);
            LogToSharedBuffer(L"[PROCESS] Match: %wZ added to tracking list. PID: %d\n",
                CreateInfo->ImageFileName, currentPid);
            LogToSharedBuffer(L"[PROCESS] launch arguments: ");
            if (CreateInfo->CommandLine != NULL) {
                LogToSharedBuffer(L"%wZ\n", CreateInfo->CommandLine);
            }
            else {
                LogToSharedBuffer(L"None\n");
            }
        }
    }
    return;
}

// Monitor (Registry)
NTSTATUS RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2) {
    UNREFERENCED_PARAMETER(CallbackContext);

    HANDLE currentProcessPid = PsGetCurrentProcessId();
    if (!isPidTracked((ULONG)(ULONG_PTR)currentProcessPid)) {
        return STATUS_SUCCESS;
    }

    REG_NOTIFY_CLASS Operation = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    switch (Operation) {
    case RegNtPreCreateKeyEx: {
        PREG_CREATE_KEY_INFORMATION Info = (PREG_CREATE_KEY_INFORMATION)Argument2;
        PCUNICODE_STRING rootName = NULL;

        if (Info->RootObject != NULL) {
            CmCallbackGetKeyObjectIDEx(&g_RegCookie, Info->RootObject, NULL, &rootName, 0);
        }

        if (rootName && rootName->Length > 0) {
            LogToSharedBuffer(L"[REGISTRY] Create Key: %wZ\\%wZ\n", rootName, Info->CompleteName);
        }
        else {
            LogToSharedBuffer(L"[REGISTRY] Create Key: %wZ\n", Info->CompleteName);
        }
        break;
    }
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION Info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        PCUNICODE_STRING keyName = NULL;
        CmCallbackGetKeyObjectIDEx(&g_RegCookie, Info->Object, NULL, &keyName, 0);

        __try {
            if (Info->Data != NULL && Info->DataSize > 0) {

                // Parcing (DWORD)
                if (Info->Type == REG_DWORD && Info->DataSize >= sizeof(ULONG)) {
                    ULONG val = *(PULONG)Info->Data;
                    LogToSharedBuffer(L"[REGISTRY] Set Value: %wZ\\%wZ (DWORD: %u)\n", keyName, Info->ValueName, val);
                }
                // Parcing (String)
                else if (Info->Type == REG_SZ || Info->Type == REG_EXPAND_SZ) {
                    ULONG chars = Info->DataSize / sizeof(WCHAR);
                    if (chars > 80) chars = 80;

                    LogToSharedBuffer(L"[REGISTRY] Set Value: %wZ\\%wZ (STRING: %.*ws)\n",
                        keyName, Info->ValueName, chars, (PWCHAR)Info->Data);
                }
                else {
                    LogToSharedBuffer(L"[REGISTRY] Set Value: %wZ\\%wZ (Type: %d, Size: %d bytes)\n",
                        keyName, Info->ValueName, Info->Type, Info->DataSize);
                }
            }
            else {
                LogToSharedBuffer(L"[REGISTRY] Set Value: %wZ\\%wZ (EMPTY DATA)\n", keyName, Info->ValueName);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LogToSharedBuffer(L"[REGISTRY] Set Value: %wZ\\%wZ <MEMORY ACCESS ERROR>\n", keyName, Info->ValueName);
        }
        break;
    }
    case RegNtPreQueryValueKey: {
        PREG_QUERY_VALUE_KEY_INFORMATION Info = (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2;
        PCUNICODE_STRING keyName = NULL;
        CmCallbackGetKeyObjectIDEx(&g_RegCookie, Info->Object, NULL, &keyName, 0);

        LogToSharedBuffer(L"[REGISTRY] Wants to Get Value: %wZ\\%wZ\n", keyName, Info->ValueName);
        break;
    }
    case RegNtPostQueryValueKey: {
        PREG_POST_OPERATION_INFORMATION PostInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;

        if (NT_SUCCESS(PostInfo->Status)) {

            PREG_QUERY_VALUE_KEY_INFORMATION PreInfo = (PREG_QUERY_VALUE_KEY_INFORMATION)PostInfo->PreInformation;
            PCUNICODE_STRING keyName = NULL;
            CmCallbackGetKeyObjectIDEx(&g_RegCookie, PostInfo->Object, NULL, &keyName, 0);

            if (PreInfo->KeyValueInformationClass == KeyValuePartialInformation && PreInfo->KeyValueInformation != NULL) {
                PKEY_VALUE_PARTIAL_INFORMATION partialInfo = (PKEY_VALUE_PARTIAL_INFORMATION)PreInfo->KeyValueInformation;

                __try {
                    if (partialInfo->Type == REG_DWORD && partialInfo->DataLength >= sizeof(ULONG)) {
                        ULONG val = *(PULONG)partialInfo->Data;
                        LogToSharedBuffer(L"[REGISTRY] Read SUCCESS: %wZ\\%wZ (DWORD: %u)\n", keyName, PreInfo->ValueName, val);
                    }
                    else if (partialInfo->Type == REG_SZ || partialInfo->Type == REG_EXPAND_SZ) {
                        ULONG chars = partialInfo->DataLength / sizeof(WCHAR);
                        if (chars > 80) chars = 80;
                        LogToSharedBuffer(L"[REGISTRY] Read SUCCESS: %wZ\\%wZ (STRING: %.*ws)\n",
                            keyName, PreInfo->ValueName, chars, (PWCHAR)partialInfo->Data);
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    LogToSharedBuffer(L"[REGISTRY] Read SUCCESS: %wZ\\%wZ <MEMORY ACCESS ERROR>\n", keyName, PreInfo->ValueName);
                }
            }
        }
        break;

    }
    }
    return STATUS_SUCCESS;
}

// Monitor (Files) (Minifilter)
FLT_PREOP_CALLBACK_STATUS PreFileOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {

    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    ULONG requestorPid = FltGetRequestorProcessId(Data);

    if (!isPidTracked(requestorPid)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;

        PFLT_FILE_NAME_INFORMATION nameInfo;
        if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
            switch (createDisposition) {
            case FILE_CREATE:
                LogToSharedBuffer(L"[FILE] Wants to: Create New: %wZ\n", &nameInfo->Name);
                break;
            case FILE_OPEN:
            case FILE_OPEN_IF:
                LogToSharedBuffer(L"[FILE] Wants to: Open Existing: %wZ\n", &nameInfo->Name);
                break;
            case FILE_OVERWRITE:
            case FILE_OVERWRITE_IF:
            case FILE_SUPERSEDE:
                LogToSharedBuffer(L"[FILE] Wants to: Overwrite: %wZ\n", &nameInfo->Name);
                break;
            default:
                LogToSharedBuffer(L"[FILE] Wants to: Unknown operation\n");
                break;
            }
            FltReleaseFileNameInformation(nameInfo);
        }
    }

    if (Data->Iopb->MajorFunction == IRP_MJ_READ) {
        if (!(Data->Iopb->IrpFlags & IRP_PAGING_IO)) {
            PFLT_FILE_NAME_INFORMATION nameInfo;
            if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
                LogToSharedBuffer(L"[FILE] Read: %wZ\n", &nameInfo->Name);
                FltReleaseFileNameInformation(nameInfo);
            }
        }
        DbgPrint("[PreFileOperation] Warning: paging isn't completed");
    }

    if (Data->Iopb->MajorFunction == IRP_MJ_READ) {
        if (!(Data->Iopb->IrpFlags & IRP_PAGING_IO)) {
            PFLT_FILE_NAME_INFORMATION nameInfo;
            if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
                LogToSharedBuffer(L"[FILE] Wants to Write: %wZ\n", &nameInfo->Name);
                FltReleaseFileNameInformation(nameInfo);
            }
        }
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS PostFileOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // If operation stopped by controller or driver unloading, exiting
    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Status of tracked operation
    NTSTATUS status = Data->IoStatus.Status;
    // Additional info about tracked operation
    ULONG_PTR information = Data->IoStatus.Information;

    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        if (NT_SUCCESS(status)) {
            if (information == FILE_CREATED) {
                LogToSharedBuffer(L"   -> [RESULT] Successfully CREATED\n");
            }
            else if (information == FILE_OPENED) {
                LogToSharedBuffer(L"   -> [RESULT] Successfully OPENED\n");
            }
            else if (information == FILE_OVERWRITTEN || information == FILE_SUPERSEDED) {
                LogToSharedBuffer(L"   -> [RESULT] Successfully OVERWRITTEN\n");
            }
            else {
                LogToSharedBuffer(L"   -> [RESULT] Success (Action code: 0x%X)\n", (int)information);
            }
        } else {
            LogToSharedBuffer(L"   -> [RESULT] FAILED! NTSTATUS: 0x%X\n", status);

            if (status == STATUS_OBJECT_NAME_NOT_FOUND) LogToSharedBuffer(L"      (File Not Found)\n");
            if (status == STATUS_ACCESS_DENIED) LogToSharedBuffer(L"      (Access Denied)\n");
        }
    }
    else if (Data->Iopb->MajorFunction == IRP_MJ_READ) {
        if (NT_SUCCESS(status)) {
            LogToSharedBuffer(L"   -> [RESULT] Read SUCCESS (%llu bytes read)\n", (ULONG64)information);
        }
        else {
            LogToSharedBuffer(L"   -> [RESULT] Read FAILED! NTSTATUS: 0x%X\n", status);
        }
    } 
    else if (Data->Iopb->MajorFunction == IRP_MJ_WRITE) {
        if (NT_SUCCESS(status)) {
            LogToSharedBuffer(L"   -> [RESULT] Write SUCCESS (%llu bytes written)\n", (ULONG64)information);
        }
        else {
            LogToSharedBuffer(L"   -> [RESULT] Write FAILED! NTSTATUS: 0x%X\n", status);
        }
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

// Monitor (Threads)
VOID ThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
    if (!isPidTracked((ULONG)(ULONG_PTR)ProcessId)) {
        return;
    }
    if (Create) {
        LogToSharedBuffer(L"[THREAD] Created: PID %p, TID %p\n", ProcessId, ThreadId);
    }
    else {
        LogToSharedBuffer(L"[THREAD] Terminated: PID %p, TID %p\n", ProcessId, ThreadId);
    }
}