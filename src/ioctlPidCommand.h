#pragma once
#include <ntddk.h>

extern ULONG g_TargetPID;

// ќбъ€вл€ем прототипы функций
NTSTATUS CreateCloseHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DeviceControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);