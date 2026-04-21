#pragma once
#include <ntddk.h>


#define IOCTL_SET_TARGET_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

ULONG g_TargetPID = 0; // 0 means monitoring is disabled by default


// 2. Standard handler to allow User-Mode to open a handle to our driver
NTSTATUS CreateCloseHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
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

    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SET_TARGET_PID) {
        // Check if the input buffer is exactly the size of ULONG (PID)
        if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(ULONG)) {

            // Extract the PID from the SystemBuffer (since we used METHOD_BUFFERED)
            ULONG* pInputPid = (ULONG*)Irp->AssociatedIrp.SystemBuffer;

            if (pInputPid != NULL) {
                g_TargetPID = *pInputPid;
                DbgPrint("[IOCTL] Target PID updated successfully to: %d\n", g_TargetPID);
                status = STATUS_SUCCESS;
                bytesIO = sizeof(ULONG);
            }
        }
        else {
            DbgPrint("[-] Invalid buffer size for IOCTL_SET_TARGET_PID\n");
            status = STATUS_INFO_LENGTH_MISMATCH;
        }
    }

    // Complete the IRP request
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesIO;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}