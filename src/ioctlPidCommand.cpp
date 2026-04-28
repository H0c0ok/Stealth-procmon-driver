#include <ntifs.h>
#include <ntstrsafe.h>
#include "ioctlPidCommand.h"
#include "Notifications.h"

#define IOCTL_SET_TARGET_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

WCHAR g_TargetProcessName[256] = { 0 };

PSHARED_MEMORY_BUFFER g_SharedBuffer = NULL;
PMDL g_SharedMdl = NULL;
PVOID g_UserMappedAddress = NULL;
KSPIN_LOCK g_EventLock;


NTSTATUS InitializeSharedMemory() {
    KeInitializeSpinLock(&g_EventLock);

    // Allocation memory in unloadable kernel pool
    g_SharedBuffer = (PSHARED_MEMORY_BUFFER)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(SHARED_MEMORY_BUFFER), 'MshS');
    if (!g_SharedBuffer) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(g_SharedBuffer, sizeof(SHARED_MEMORY_BUFFER));
    return STATUS_SUCCESS;
}

VOID FreeSharedMemory() {
    if (g_SharedMdl) {
        IoFreeMdl(g_SharedMdl);
    }
    if (g_SharedBuffer) {
        ExFreePoolWithTag(g_SharedBuffer, 'MshS');
    }
}

VOID WriteEventToBuffer(MONITOR_EVENT* event) {
    if (!g_SharedBuffer) return;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_EventLock, &oldIrql);

    ULONG nextWriteIndex = (g_SharedBuffer->WriteIndex + 1) % MAX_EVENTS;

    if (nextWriteIndex == g_SharedBuffer->ReadIndex) {
        g_SharedBuffer->DroppedEvents++;
    }
    else {
        RtlCopyMemory(&g_SharedBuffer->Events[g_SharedBuffer->WriteIndex], event, sizeof(MONITOR_EVENT));
        g_SharedBuffer->WriteIndex = nextWriteIndex;
    }
    KeReleaseSpinLock(&g_EventLock, oldIrql);

}

// Standard handler to allow User-Mode to open a handle to our driver
NTSTATUS CreateCloseHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    if (stack->MajorFunction == IRP_MJ_CLEANUP || stack->MajorFunction == IRP_MJ_CLOSE) {
        if (g_SharedMdl && g_UserMappedAddress) {
            MmUnmapLockedPages(g_UserMappedAddress, g_SharedMdl);
            IoFreeMdl(g_SharedMdl);

            g_SharedMdl = NULL;
            g_UserMappedAddress = NULL;
            DbgPrint("[DRIVER] Memory unmapped due to process cleanup.\n");
        }
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


NTSTATUS DeviceControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG bytesIO = 0;

    // Get the current I/O stack location
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SET_TARGET_PID) {
        // Check if the input buffer is exactly the size of ULONG (PID)
        if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(ULONG)) {

            // Extract the PID from the SystemBuffer (since we used METHOD_BUFFERED)
            ULONG* pInputPid = (ULONG*)Irp->AssociatedIrp.SystemBuffer;

            if (pInputPid != NULL) {
                AddTrackedPid(*pInputPid);
                status = STATUS_SUCCESS;
                bytesIO = sizeof(ULONG);
            }
        }
        else {
            status = STATUS_INFO_LENGTH_MISMATCH;
        }
    }
    else if (controlCode == IOCTL_SET_TARGET_NAME) {
        ULONG nameLength = stack->Parameters.DeviceIoControl.InputBufferLength;

        // Check for string to fitting into buffer
        if (nameLength > 0 && nameLength <= sizeof(g_TargetProcessName)) {
            WCHAR* pInputName = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;

            if (pInputName != NULL) {
                // Setting new name after clening older one
                RtlZeroMemory(g_TargetProcessName, sizeof(g_TargetProcessName));
                RtlCopyMemory(g_TargetProcessName, pInputName, nameLength);

                // Adding null-terminator to end of string
                g_TargetProcessName[(sizeof(g_TargetProcessName) / sizeof(WCHAR)) - 1] = L'\0';

                status = STATUS_SUCCESS;
                bytesIO = nameLength;
            }
        }
    }
    else if (controlCode == IOCTL_MAP_MEMORY) {
        if (!g_SharedBuffer) {
            status = STATUS_UNSUCCESSFUL;
        }
        else if (g_UserMappedAddress != NULL) {
            *(PVOID*)Irp->AssociatedIrp.SystemBuffer = g_UserMappedAddress;
            status = STATUS_SUCCESS;
            bytesIO = sizeof(PVOID);
        }
        else {
            g_SharedMdl = IoAllocateMdl(g_SharedBuffer, sizeof(SHARED_MEMORY_BUFFER), FALSE, FALSE, NULL);
            if (g_SharedMdl) {
                MmBuildMdlForNonPagedPool(g_SharedMdl);
                __try {
                    g_UserMappedAddress = MmMapLockedPagesSpecifyCache(g_SharedMdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);

                    // Return ponter to user mode program
                    *(PVOID*)Irp->AssociatedIrp.SystemBuffer = g_UserMappedAddress;
                    status = STATUS_SUCCESS;
                    bytesIO = sizeof(PVOID);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    IoFreeMdl(g_SharedMdl);
                    g_SharedMdl = NULL;
                    status = STATUS_UNSUCCESSFUL;
                }
            }
            else {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
        }
    }
    else if (controlCode == IOCTL_UNMAP_MEMORY) {
        if (g_SharedMdl && g_UserMappedAddress) {
            MmUnmapLockedPages(g_UserMappedAddress, g_SharedMdl);
            IoFreeMdl(g_SharedMdl);
            g_SharedMdl = NULL;
            g_UserMappedAddress = NULL;
        }
        status = STATUS_SUCCESS;
    }
    else {
        status = STATUS_INFO_LENGTH_MISMATCH;
    }

    // Complete the IRP request
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesIO;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}