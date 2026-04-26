#pragma once
#include <ntifs.h>
#include "SharedDefines.h"

extern ULONG g_TargetPID;
extern WCHAR g_TargetProcessName[256];

#define IOCTL_SET_TARGET_PID  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_TARGET_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)


extern PSHARED_MEMORY_BUFFER g_SharedBuffer;
extern PMDL g_SharedMdl;
extern PVOID g_UserMappedAddress;
extern KSPIN_LOCK g_EventLock;

NTSTATUS InitializeSharedMemory();
VOID FreeSharedMemory();
VOID LogToSharedBuffer(PCWSTR Format, ...);
VOID WriteEventToBuffer(MONITOR_EVENT*);

NTSTATUS CreateCloseHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DeviceControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);