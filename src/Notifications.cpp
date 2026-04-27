#include <ntifs.h>
#include <fltkernel.h>
#include <ntstrsafe.h>
#include "Notifications.h"
#include "ioctlPidCommand.h"

ULONG g_TrackedPIDs[MAX_TRACKED_PIDS] = { 0 };
ULONG g_TrackedPIDCount = 0;
KSPIN_LOCK g_PidLock;

BOOLEAN isPidTracked(ULONG Pid) {
    if (Pid == 0) return FALSE;
    
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
    if (Pid == 0) { return; }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_PidLock, &oldIrql);

    BOOLEAN found = FALSE;
    for (ULONG i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (g_TrackedPIDs[i] == Pid) { found = TRUE; break; }
    }

    if (!found) {
        BOOLEAN added = FALSE;
        for (ULONG i = 0; i < MAX_TRACKED_PIDS; i++) {
            if (g_TrackedPIDs[i] == 0) {
                g_TrackedPIDs[i] = Pid;
                g_TrackedPIDCount++;
                added = TRUE;
                break;
            }
        }
        if (!added) {
            // TODO: DbgPrint must be outside of spinlock
            DbgPrint("[AddTrackedPid] Tracked PIDs array is full. Cannot add PID: %d\n", Pid);
        }
    }
    KeReleaseSpinLock(&g_PidLock, oldIrql);
}

VOID RemoveTrackedPid(ULONG Pid) {
    if (Pid == 0) return;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_PidLock, &oldIrql);

    BOOLEAN removed = FALSE;
    for (ULONG i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (g_TrackedPIDs[i] == Pid) {
            g_TrackedPIDs[i] = 0;
            removed = TRUE;
            break;
        }
    }

    if (removed && g_TrackedPIDCount > 0) {
        g_TrackedPIDCount--;
    }

    KeReleaseSpinLock(&g_PidLock, oldIrql);
}

// monitor (Process)
VOID ProcessNotifyCallbackEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);

    MONITOR_EVENT processEvent = { 0 };
    ULONG currentPid = (ULONG)(ULONG_PTR)ProcessId;
    KeQuerySystemTime(&processEvent.TimeStamp);

    if (CreateInfo == NULL) {
        if (isPidTracked(currentPid)) {
            RemoveTrackedPid(currentPid);
            // LogToSharedBuffer(L"[PROCESS] Tracked process terminated, removed from list. PID: %d\n", currentPid);
            processEvent.ProcessId = currentPid;
            processEvent.Type = EProcessExit;
            WriteEventToBuffer(&processEvent);
        }
        return;
    }

    ULONG parentPid = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;
   

    if (isPidTracked(parentPid)) {
        AddTrackedPid(currentPid);
        processEvent.ProcessId = currentPid;
        processEvent.Data.Process.ParentPid = parentPid;
        processEvent.Type = EProcessCreate;
        processEvent.Data.Process.IsInherited = 1;

        // LogToSharedBuffer(L"[PROCESS] Child process %wZ (PID: %d) inherit tracking.\n", CreateInfo->ImageFileName, currentPid);
        if (CreateInfo->ImageFileName != NULL) {
            // LogToSharedBuffer(L"[PROCESS] launch arguments: %wZ\n", CreateInfo->CommandLine);
            ULONG ImageNameLength = min(CreateInfo->ImageFileName->Length,
                sizeof(processEvent.Data.Process.ImageName) - sizeof(WCHAR));

            RtlCopyMemory(processEvent.Data.Process.ImageName,
                CreateInfo->ImageFileName->Buffer, ImageNameLength);
            processEvent.Data.Process.ImageName[ImageNameLength / sizeof(WCHAR)] = L'\0';
        } else {
            // LogToSharedBuffer(L"[PROCESS] launch arguments: None\n");
            RtlStringCbCopyW(processEvent.Data.Process.ImageName,
                sizeof(processEvent.Data.Process.ImageName), L"Unknown");
        }

        if (CreateInfo->CommandLine != NULL && CreateInfo->CommandLine->Length > 0) {
            ULONG commandLenghtMax = sizeof(processEvent.Data.Process.CommandLine) - sizeof(WCHAR);
            ULONG commandLenght = min(CreateInfo->CommandLine->Length, commandLenghtMax);

            RtlCopyMemory(processEvent.Data.Process.CommandLine,
                CreateInfo->CommandLine->Buffer, commandLenght);
            processEvent.Data.Process.CommandLine[commandLenght / sizeof(WCHAR)] = L'\0';
        }
        else {
            RtlStringCbCopyW(processEvent.Data.Process.CommandLine,
                sizeof(processEvent.Data.Process.CommandLine), L"None");
        }

        WriteEventToBuffer(&processEvent);
        return;
    }

    if (CreateInfo->ImageFileName != NULL && g_TargetProcessName[0] != L'\0') {
        UNICODE_STRING targetNameU;
        RtlInitUnicodeString(&targetNameU, g_TargetProcessName);

        if (RtlSuffixUnicodeString(&targetNameU, CreateInfo->ImageFileName, TRUE)) {
            USHORT diffBytes = CreateInfo->ImageFileName->Length - targetNameU.Length;
            if (diffBytes == 0 || CreateInfo->ImageFileName->Buffer[(diffBytes / sizeof(WCHAR)) - 1] == L'\\') {
                AddTrackedPid(currentPid);

                processEvent.ProcessId = currentPid;
                processEvent.Data.Process.ParentPid = parentPid;
                processEvent.Type = EProcessCreate;
                processEvent.Data.Process.IsInherited = 0;

                ULONG ImageNameLengthMax = sizeof(processEvent.Data.Process.ImageName) - sizeof(WCHAR);
                ULONG ImageNameLength = min(CreateInfo->ImageFileName->Length,
                    ImageNameLengthMax);

                RtlCopyMemory(processEvent.Data.Process.ImageName,
                    CreateInfo->ImageFileName->Buffer, ImageNameLength);
                processEvent.Data.Process.ImageName[ImageNameLength / sizeof(WCHAR)] = L'\0';

                if ((CreateInfo->CommandLine != NULL) && (CreateInfo->CommandLine->Length > 0)) {
                    
                    ULONG commandLenghtMax = sizeof(processEvent.Data.Process.CommandLine) - sizeof(WCHAR);
                    ULONG commandLenght = min(CreateInfo->CommandLine->Length,
                        commandLenghtMax);

                    RtlCopyMemory(processEvent.Data.Process.CommandLine,
                        CreateInfo->CommandLine->Buffer, commandLenght);
                    processEvent.Data.Process.CommandLine[commandLenght / sizeof(WCHAR)] = L'\0';
                }
                else {
                    RtlStringCbCopyW(processEvent.Data.Process.CommandLine,
                        sizeof(processEvent.Data.Process.CommandLine), L"None");
                }
                WriteEventToBuffer(&processEvent);
            }
        }
        return;
    }
}

// Monitor (Registry)
NTSTATUS RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2) {
    UNREFERENCED_PARAMETER(CallbackContext);

    HANDLE currentProcessPid = PsGetCurrentProcessId();
    if (!isPidTracked((ULONG)(ULONG_PTR)currentProcessPid)) {
        return STATUS_SUCCESS;
    }

    MONITOR_EVENT registryEvent = { 0 };
    KeQuerySystemTime(&registryEvent.TimeStamp);
    registryEvent.ProcessId = (ULONG)(ULONG_PTR)currentProcessPid;

    REG_NOTIFY_CLASS Operation = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    switch (Operation) {

    case RegNtPreQueryMultipleValueKey: {
        PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION preInfo = (PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION)Argument2;
        PCUNICODE_STRING keyName = NULL;

        CmCallbackGetKeyObjectIDEx(&g_RegCookie, preInfo->Object, NULL, &keyName, 0);

        if (keyName) {
            RtlStringCbPrintfW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path), L"%wZ", keyName);
        }

        registryEvent.Data.Registry.DataSize = preInfo->EntryCount;
        registryEvent.Type = ERegistryPreQueryMultipleValueKey;
        WriteEventToBuffer(&registryEvent);
        //LogToSharedBuffer(L"[REGISTRY] Process wants to query multiply values: <values>");
        break;
    }
    case RegNtPostQueryMultipleValueKey: {
        
        PREG_POST_OPERATION_INFORMATION PostInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
        PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION PreInfo = (PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION)PostInfo->PreInformation;

        PCUNICODE_STRING keyName = NULL;
        CmCallbackGetKeyObjectIDEx(&g_RegCookie, PostInfo->Object, NULL, &keyName, 0);

        registryEvent.Type = ERegistryPostQueryMultipleValueKey;
        registryEvent.Data.Registry.Status = PostInfo->Status;

        if (keyName) {
            RtlStringCbPrintfW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path), L"%wZ", keyName);
        }

        if (NT_SUCCESS(PostInfo->Status)) {
            registryEvent.Data.Registry.DataSize = PreInfo->EntryCount;
            RtlStringCbCopyW(registryEvent.Data.Registry.StringData,
                sizeof(registryEvent.Data.Registry.StringData), L"Multiple values read");
        }
        else {
            registryEvent.Data.Registry.DataSize = 0;
            RtlStringCbCopyW(registryEvent.Data.Registry.StringData,
                sizeof(registryEvent.Data.Registry.StringData), L"Failed to read");
        }

        WriteEventToBuffer(&registryEvent);

        //LogToSharedBuffer(L"[REGISTRY] Process queryed multiply values: <values>");
        break;
    }
    case RegNtPreEnumerateKey: {
        PREG_ENUMERATE_KEY_INFORMATION Info = (PREG_ENUMERATE_KEY_INFORMATION)Argument2;
        PCUNICODE_STRING keyName = NULL;
        CmCallbackGetKeyObjectIDEx(&g_RegCookie, Info->Object, NULL, &keyName, 0);

        registryEvent.Type = ERegistryPreEnumerateKey;

        if (keyName) {
            RtlStringCbPrintfW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path), L"%wZ", keyName);
        }

        // Info->Index shows, which folder by order enumerates process (0, 1, 2...)
        registryEvent.Data.Registry.DwordData = Info->Index;

        WriteEventToBuffer(&registryEvent);
        // LogToSharedBuffer(L"[REGISTRY] Process wants to enumerate keys: <value>");
        break;
    }
    case RegNtPostEnumerateKey: {
        PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
        PREG_ENUMERATE_KEY_INFORMATION preInfo = (PREG_ENUMERATE_KEY_INFORMATION)postInfo->PreInformation;

        PCUNICODE_STRING keyName = NULL;
        CmCallbackGetKeyObjectIDEx(&g_RegCookie, postInfo->Object, NULL, &keyName, 0);
        registryEvent.Type = ERegistryPostEnumerateKey;
        registryEvent.Data.Registry.Status = postInfo->Status;
        if (keyName) {
            RtlStringCbPrintfW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path), L"%wZ", keyName);
        }
        else {
            RtlStringCbPrintfW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path), L"Unknown");
        }

        registryEvent.Data.Registry.DwordData = preInfo->Index;

        if (NT_SUCCESS(postInfo->Status)) {
            RtlStringCbCopyW(registryEvent.Data.Registry.StringData, 
                sizeof(registryEvent.Data.Registry.StringData), L"Enum sucess");
        }
        else {
            RtlStringCbCopyW(registryEvent.Data.Registry.StringData,
                sizeof(registryEvent.Data.Registry.StringData), L"Enum end/error");
        }

        WriteEventToBuffer(&registryEvent);
        if (keyName) {
            CmCallbackReleaseKeyObjectIDEx(keyName);
        }
        break;
    }
    case RegNtPreCreateKeyEx: {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)Argument2;
        PCUNICODE_STRING rootName = NULL;
        registryEvent.Type = ERegistryPreCreateKey;

        if (info->RootObject != NULL) {
            CmCallbackGetKeyObjectIDEx(&g_RegCookie, info->RootObject, NULL, &rootName, 0);
        }

        if (rootName && rootName->Length > 0) {
            // LogToSharedBuffer(L"[REGISTRY] Create Key: %wZ\\%wZ\n", rootName, info->CompleteName);
            RtlStringCbPrintfW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path), L"%wZ\\%wZ", rootName, info->CompleteName);
        }
        else {
            // LogToSharedBuffer(L"[REGISTRY] Create Key: %wZ\n", info->CompleteName);
            RtlStringCbPrintfW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path),
                L"%wZ",
                info->CompleteName);
        }
        WriteEventToBuffer(&registryEvent);
        if (rootName) {
            CmCallbackReleaseKeyObjectIDEx(rootName);
        }
        break;
    }
    case RegNtPostCreateKeyEx: {
        PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
        PREG_CREATE_KEY_INFORMATION preInfo = (PREG_CREATE_KEY_INFORMATION)postInfo->PreInformation;
        PCUNICODE_STRING rootName = NULL;
        registryEvent.Type = ERegistryPostCreateKey;
        registryEvent.Data.Registry.Status = postInfo->Status;

        if (preInfo->RootObject != NULL) {
            CmCallbackGetKeyObjectIDEx(&g_RegCookie, preInfo->RootObject, NULL, &rootName, 0);
        }

        if (rootName && rootName->Length > 0) {
            RtlStringCbPrintfW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path),
                L"%wZ\\%wZ",
                rootName,
                preInfo->CompleteName);
        }
        else {
            RtlStringCbPrintfW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path),
                L"%wZ",
                preInfo->CompleteName);
        }
        WriteEventToBuffer(&registryEvent);
        if (rootName) {
            CmCallbackReleaseKeyObjectIDEx(rootName);
        }
        break;
    }
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        PCUNICODE_STRING keyName = NULL;

        registryEvent.Type = ERegistryPreSetValue;

        CmCallbackGetKeyObjectIDEx(&g_RegCookie, info->Object, NULL, &keyName, 0);

        if (keyName) {
            RtlStringCbPrintfW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path), L"%wZ", keyName);
        }
        else {
            RtlStringCbCopyW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path), L"Unknown path");
        }

        if (info->ValueName) {
            RtlStringCbPrintfW(registryEvent.Data.Registry.ValueName,
                sizeof(registryEvent.Data.Registry.ValueName), L"%wZ", info->ValueName);
        }
        else {
            RtlStringCbCopyW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path), L"Unknown value");
        }

        registryEvent.Data.Registry.DataType = info->Type;
        registryEvent.Data.Registry.DataSize = info->DataSize;



        __try {
            if (info->Data != NULL && info->DataSize > 0) {

                // Parcing (DWORD)
                if (info->Type == REG_DWORD && info->DataSize >= sizeof(ULONG)) {
                    // LogToSharedBuffer(L"[REGISTRY] Set Value: %wZ\\%wZ (DWORD: %u)\n", keyName, Info->ValueName, val);
                    registryEvent.Data.Registry.DwordData = *(PULONG)info->Data;
                }
                // Parcing (String)
                else if (info->Type == REG_SZ || info->Type == REG_EXPAND_SZ) {
                    
                    ULONG copyLength = min(info->DataSize,
                        sizeof(registryEvent.Data.Registry.StringData));

                    RtlCopyMemory(registryEvent.Data.Registry.StringData, info->Data, copyLength);

                    registryEvent.Data.Registry.StringData[copyLength / sizeof(WCHAR)] = L'\0';
                    // LogToSharedBuffer(L"[REGISTRY] Set Value: %wZ\\%wZ (STRING: %.*ws)\n",
                    //    keyName, info->ValueName, chars, (PWCHAR)info->Data);
                }
            }
            else {
                // LogToSharedBuffer(L"[REGISTRY] Set Value: %wZ\\%wZ (EMPTY DATA)\n", keyName, info->ValueName);
                RtlStringCbCopyW(registryEvent.Data.Registry.StringData,
                    sizeof(registryEvent.Data.Registry.StringData), L"empty value");
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // LogToSharedBuffer(L"[REGISTRY] Set Value: %wZ\\%wZ <MEMORY ACCESS ERROR>\n", keyName, info->ValueName);
            RtlStringCbCopyW(registryEvent.Data.Registry.StringData, sizeof(registryEvent.Data.Registry.StringData), L"Memory access error");
        }
        WriteEventToBuffer(&registryEvent);
        if (keyName) {
            CmCallbackReleaseKeyObjectIDEx(keyName);
        }
        break;
    }
    case RegNtPostSetValueKey: {
        PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
        PREG_SET_VALUE_KEY_INFORMATION preInfo = (PREG_SET_VALUE_KEY_INFORMATION)postInfo->PreInformation;

        PCUNICODE_STRING keyName = NULL;
        CmCallbackGetKeyObjectIDEx(&g_RegCookie, postInfo->Object, NULL, &keyName, 0);

        registryEvent.Type = ERegistryPostSetValue;
        registryEvent.Data.Registry.Status = postInfo->Status;

        if (keyName) {
            RtlStringCbPrintfW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path),
                L"%wZ",
                keyName);
        }
        else {
            RtlStringCbCopyW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path),
                L"Unkwon path");
        }

        if (preInfo->ValueName) {
            RtlStringCbPrintfW(registryEvent.Data.Registry.ValueName,
                sizeof(registryEvent.Data.Registry.ValueName),
                L"%wZ",
                preInfo->ValueName);
        }
        else {
            RtlStringCbCopyW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path),
                L"Default value");
        }

        WriteEventToBuffer(&registryEvent);
        if (keyName) {
            CmCallbackReleaseKeyObjectIDEx(keyName);
        }
        break;
    }
    case RegNtPreQueryValueKey: {
        PREG_QUERY_VALUE_KEY_INFORMATION info = (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2;
        PCUNICODE_STRING keyName = NULL;
        CmCallbackGetKeyObjectIDEx(&g_RegCookie, info->Object, NULL, &keyName, 0);

        // LogToSharedBuffer(L"[REGISTRY] Wants to Get Value: %wZ\\%wZ\n", keyName, Info->ValueName);
        
        registryEvent.Type = ERegistryPreQueryValueKey;
        
        if (keyName) {
            RtlStringCbPrintfW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path), L"%wZ", keyName);
        }
        else {
            RtlStringCbCopyW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path), L"Unknown path");
        }

        if (info->ValueName) {
            RtlStringCbPrintfW(registryEvent.Data.Registry.ValueName,
                sizeof(registryEvent.Data.Registry.ValueName), L"%wZ", info->ValueName);
        }
        else {
            RtlStringCbCopyW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path), L"Default value");
        }
        
        WriteEventToBuffer(&registryEvent);
        if (keyName) {
            CmCallbackReleaseKeyObjectIDEx(keyName);
        }
        break;
    }
    case RegNtPostQueryValueKey: {
        PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
        PREG_QUERY_VALUE_KEY_INFORMATION preInfo = (PREG_QUERY_VALUE_KEY_INFORMATION)postInfo->PreInformation;
        PCUNICODE_STRING keyName = NULL;
        CmCallbackGetKeyObjectIDEx(&g_RegCookie, postInfo->Object, NULL, &keyName, 0);

        registryEvent.Type = ERegistryPostQueryValueKey;
        registryEvent.Data.Registry.Status = postInfo->Status;

        if (keyName) {
            RtlStringCbPrintfW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path), L"%wZ", keyName);
        }
        else {
            RtlStringCbCopyW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path), L"Unknown path");
        }

        if (preInfo->ValueName && preInfo->ValueName->Length > 0) {
            RtlStringCbPrintfW(registryEvent.Data.Registry.ValueName,
                sizeof(registryEvent.Data.Registry.ValueName), L"%wZ", preInfo->ValueName);
        }
        else {
            RtlStringCbCopyW(registryEvent.Data.Registry.ValueName,
                sizeof(registryEvent.Data.Registry.ValueName), L"Default value");
        }

        if (NT_SUCCESS(postInfo->Status)) {
            if (preInfo->KeyValueInformationClass == KeyValuePartialInformation && preInfo->KeyValueInformation != NULL) {
                PKEY_VALUE_PARTIAL_INFORMATION partialInfo = (PKEY_VALUE_PARTIAL_INFORMATION)preInfo->KeyValueInformation;

                __try {
                    if (partialInfo->Type == REG_DWORD && partialInfo->DataLength >= sizeof(ULONG)) {
                        registryEvent.Data.Registry.DwordData = *(PULONG)partialInfo->Data;
                    }
                    else if (partialInfo->Type == REG_SZ || partialInfo->Type == REG_EXPAND_SZ) {
                        ULONG copyLength = min(partialInfo->DataLength,
                            sizeof(registryEvent.Data.Registry.StringData) - sizeof(WCHAR));
                        RtlCopyMemory(registryEvent.Data.Registry.StringData,
                            partialInfo->Data, copyLength);
                        registryEvent.Data.Registry.StringData[copyLength / sizeof(WCHAR)] = L'\0';
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    RtlStringCbCopyW(registryEvent.Data.Registry.StringData,
                        sizeof(registryEvent.Data.Registry.StringData),
                        L"Memory access error");
                }
            }
        }
        WriteEventToBuffer(&registryEvent);
        if (keyName) {
            CmCallbackReleaseKeyObjectIDEx(keyName);
        }
        break;
    }
    case RegNtPreDeleteValueKey: {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        PCUNICODE_STRING keyName = NULL;
        registryEvent.Type = ERegistryPreDeleteValue;
        CmCallbackGetKeyObjectIDEx(&g_RegCookie, info->Object, NULL, &keyName, 0);

        if (keyName) {
            RtlStringCbPrintfW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path),
                L"%wZ", keyName);
        }
        else {
            RtlStringCbCopyW(registryEvent.Data.Registry.Path, sizeof(registryEvent.Data.Registry.Path), L"Unknown path");
        }

        if (info->ValueName && info->ValueName->Length > 0) {
            RtlStringCbPrintfW(registryEvent.Data.Registry.ValueName,
                sizeof(registryEvent.Data.Registry.ValueName),
                L"%wZ", info->ValueName);
        }
        else {
            RtlStringCbCopyW(registryEvent.Data.Registry.ValueName,
                sizeof(registryEvent.Data.Registry.ValueName),
                L"Default value");
        }
        RtlStringCbCopyW(registryEvent.Data.Registry.StringData,
            sizeof(registryEvent.Data.Registry.StringData),
            L"Delete pending");
        WriteEventToBuffer(&registryEvent);
        if (keyName) {
            CmCallbackReleaseKeyObjectIDEx(keyName);
        }
        break;
    }

    case RegNtPostDeleteValueKey: {
        PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
        PREG_DELETE_VALUE_KEY_INFORMATION preInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)postInfo->PreInformation;

        PCUNICODE_STRING keyName = NULL;
        CmCallbackGetKeyObjectIDEx(&g_RegCookie, postInfo->Object, NULL, &keyName, 0);

        registryEvent.Type = ERegistryPostDeleteValue;
        registryEvent.Data.Registry.Status = postInfo->Status;

        if (keyName) {
            RtlStringCbPrintfW(registryEvent.Data.Registry.Path,
                sizeof(registryEvent.Data.Registry.Path), L"%wZ", keyName);
        }
        else {
            RtlStringCbCopyW(registryEvent.Data.Registry.Path, 
                sizeof(registryEvent.Data.Registry.Path), L"Unknown path");
        }

        if (preInfo->ValueName && preInfo->ValueName->Length > 0) {
            RtlStringCbPrintfW(registryEvent.Data.Registry.ValueName,
                sizeof(registryEvent.Data.Registry.ValueName), L"%wZ", preInfo->ValueName);
        }
        else {
            RtlStringCbCopyW(registryEvent.Data.Registry.ValueName,
                sizeof(registryEvent.Data.Registry.ValueName), L"Default value");
        }

        if (NT_SUCCESS(postInfo->Status)) {
            RtlStringCbCopyW(registryEvent.Data.Registry.StringData,
                sizeof(registryEvent.Data.Registry.StringData),
                L"Delete success");
        }
        else {
            RtlStringCbCopyW(registryEvent.Data.Registry.StringData,
                sizeof(registryEvent.Data.Registry.StringData),
                L"Delete failed");
        }
        WriteEventToBuffer(&registryEvent);
        if (keyName) {
            CmCallbackReleaseKeyObjectIDEx(keyName);
        }
        break;
    }

    default: {
        registryEvent.Type = ERegistryUnknown;
        registryEvent.Data.Registry.DwordData = (ULONG)Operation;
        RtlStringCbCopyW(registryEvent.Data.Registry.Path,
            sizeof(registryEvent.Data.Registry.Path), L"Unhadnled operation");
        WriteEventToBuffer(&registryEvent);
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

    MONITOR_EVENT fileEvent = { 0 };
    fileEvent.ProcessId = requestorPid;
    KeQuerySystemTime(&fileEvent.TimeStamp);

    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;

        PFLT_FILE_NAME_INFORMATION nameInfo;
        if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
            
            FltParseFileNameInformation(nameInfo);

            RtlStringCbPrintfW(fileEvent.Data.File.FilePath,
                sizeof(fileEvent.Data.File.FilePath), L"%wZ", &nameInfo->Name);
            
            switch (createDisposition) {
            case FILE_CREATE:
                //LogToSharedBuffer(L"[FILE] Wants to: Create New: %wZ\n", &nameInfo->Name);
                fileEvent.Type = EFilePreCreate;
                
                break;
            case FILE_OPEN:
            case FILE_OPEN_IF:
                //LogToSharedBuffer(L"[FILE] Wants to: Open Existing: %wZ\n", &nameInfo->Name);
                fileEvent.Type = EFilePreOpen;
                break;
            case FILE_OVERWRITE:
            case FILE_OVERWRITE_IF:
            case FILE_SUPERSEDE:
                //LogToSharedBuffer(L"[FILE] Wants to: Overwrite: %wZ\n", &nameInfo->Name);
                fileEvent.Type = EFilePreWrite;
                break;
            default:
                // LogToSharedBuffer(L"[FILE] Wants to: Unknown operation\n");
                fileEvent.Type = EFileUnknown;
                break;
            }
            FltReleaseFileNameInformation(nameInfo);
            WriteEventToBuffer(&fileEvent);
        }
    }
    else if (Data->Iopb->MajorFunction == IRP_MJ_READ) {
        if (!(Data->Iopb->IrpFlags & IRP_PAGING_IO)) {
            PFLT_FILE_NAME_INFORMATION nameInfo;

            if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
                //LogToSharedBuffer(L"[FILE] Read: %wZ\n", &nameInfo->Name);
                fileEvent.Type = EFilePreRead;
                FltParseFileNameInformation(nameInfo);
                RtlStringCbPrintfW(fileEvent.Data.File.FilePath,
                    sizeof(fileEvent.Data.File.FilePath), L"%wZ", &nameInfo->Name);

                FltReleaseFileNameInformation(nameInfo);
                WriteEventToBuffer(&fileEvent);
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

    ULONG requestorPid = FltGetRequestorProcessId(Data);

    // 2. Проверяем, отслеживаем ли мы этот процесс
    if (!isPidTracked(requestorPid)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    MONITOR_EVENT fileEvent = { 0 };
    fileEvent.ProcessId = requestorPid;
    KeQuerySystemTime(&fileEvent.TimeStamp);


    // Status of tracked operation
    fileEvent.Data.File.Status = Data->IoStatus.Status;

    // Additional info about tracked operation
    fileEvent.Data.File.Information = Data->IoStatus.Information;

    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        fileEvent.Type = EFilePostCreate;
        PFLT_FILE_NAME_INFORMATION nameInfo;

        if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
            FltParseFileNameInformation(nameInfo);
            RtlStringCbPrintfW(fileEvent.Data.File.FilePath, 
                sizeof(fileEvent.Data.File.FilePath), L"%wZ", &nameInfo->Name);
            FltReleaseFileNameInformation(nameInfo);
        }
        else {
            RtlStringCbCopyW(fileEvent.Data.File.FilePath, 
                sizeof(fileEvent.Data.File.FilePath), L"Unknown path");
        }
    }
    else if (Data->Iopb->MajorFunction == IRP_MJ_READ) {
        fileEvent.Type = EFilePostRead;
    } 
    else if (Data->Iopb->MajorFunction == IRP_MJ_WRITE) {
        fileEvent.Type = EFilePostWrite;
    }
    WriteEventToBuffer(&fileEvent);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

// Monitor (Threads)
VOID ThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
    if (!isPidTracked((ULONG)(ULONG_PTR)ProcessId)) {
        return;
    }

    MONITOR_EVENT threadEvent = { 0 };
    threadEvent.ProcessId = (ULONG)(ULONG_PTR)ProcessId;
    KeQuerySystemTime(&threadEvent.TimeStamp);

    threadEvent.Data.Thread.ThreadId = (ULONG)(ULONG_PTR)ThreadId;

    if (Create) {
        // LogToSharedBuffer(L"[THREAD] Created: PID %p, TID %p\n", ProcessId, ThreadId);
        threadEvent.Type = EThreadCreate;

    }
    else {
        // LogToSharedBuffer(L"[THREAD] Terminated: PID %p, TID %p\n", ProcessId, ThreadId);
        threadEvent.Type = EThreadExit;
    }
    WriteEventToBuffer(&threadEvent);
}