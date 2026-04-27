#pragma once
#include <ntifs.h>
#include "SharedDefines.h"

extern ULONG g_TargetPID;
extern WCHAR g_TargetProcessName[256];



extern PSHARED_MEMORY_BUFFER g_SharedBuffer;
extern PMDL g_SharedMdl;
extern PVOID g_UserMappedAddress;
extern KSPIN_LOCK g_EventLock;

NTSTATUS InitializeSharedMemory();
VOID FreeSharedMemory();
VOID WriteEventToBuffer(MONITOR_EVENT*);

NTSTATUS CreateCloseHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DeviceControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);