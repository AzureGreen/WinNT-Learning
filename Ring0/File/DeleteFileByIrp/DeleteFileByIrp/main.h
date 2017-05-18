#pragma once
#include <ntifs.h>

NTSTATUS 
DeleteFileByIrp(IN WCHAR * wzFilePath);

NTSTATUS
IrpCompleteRoutine(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);

VOID
UnloadDriver(IN PDRIVER_OBJECT DriverObject);
