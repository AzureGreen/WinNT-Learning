#include "main.h"


NTSTATUS
DriverEntry(IN PDRIVER_OBJECT  DriverObject, IN PUNICODE_STRING  RegisterPath)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	DriverObject->DriverUnload = UnloadDriver;

	Status = DeleteFileByIrp(L"\\??\\C:\\1.txt");     // 注意路径格式

	return Status;
}


NTSTATUS
DeleteFileByIrp(IN WCHAR* wzFilePath)
{
	NTSTATUS          Status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING    uniFilePath = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };
	HANDLE            FileHandle = NULL;
	IO_STATUS_BLOCK   IoStatusBlock = { 0 };

	// 通过路径获得句柄
	RtlInitUnicodeString(&uniFilePath, wzFilePath);
	InitializeObjectAttributes(&oa, &uniFilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = IoCreateFile(&FileHandle, FILE_READ_ATTRIBUTES, &oa, &IoStatusBlock,
		0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN, 0, NULL, 0,
		CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
	if (NT_SUCCESS(Status))
	{
		PFILE_OBJECT   FileObject = NULL;
		PDEVICE_OBJECT DeviceObject = NULL;

		// 获得文件对象
		Status = ObReferenceObjectByHandle(FileHandle, DELETE, *IoFileObjectType, KernelMode, &FileObject, NULL);
		if (NT_SUCCESS(Status))
		{
			DeviceObject = IoGetRelatedDeviceObject(FileObject);   // 文件系统栈最上层的设备对象
			if (DeviceObject)
			{
				PIRP   Irp = NULL;
				KEVENT Event = { 0 };
				PIO_STACK_LOCATION IrpStack = NULL;
				FILE_DISPOSITION_INFORMATION fdi = { 0 };

				// 构建一个 Irp

				Irp = IoAllocateIrp(DeviceObject->StackSize, TRUE);
				if (Irp)
				{
					fdi.DeleteFile = TRUE;

					KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

					Irp->AssociatedIrp.SystemBuffer = &fdi;
					Irp->UserEvent = &Event;
					Irp->UserIosb = &IoStatusBlock;
					Irp->Tail.Overlay.OriginalFileObject = FileObject;
					Irp->Tail.Overlay.Thread = PsGetCurrentThread();
					Irp->RequestorMode = KernelMode;
					
					IrpStack = IoGetNextIrpStackLocation(Irp);
					IrpStack->DeviceObject = DeviceObject;    // 保存文件系统设备对象
					IrpStack->FileObject = FileObject;
					IrpStack->MajorFunction = IRP_MJ_SET_INFORMATION;
					IrpStack->Parameters.SetFile.FileObject = FileObject;
					IrpStack->Parameters.SetFile.Length = sizeof(FILE_DISPOSITION_INFORMATION);
					IrpStack->Parameters.SetFile.FileInformationClass = FileDispositionInformation;

					IoSetCompletionRoutine(Irp, IrpCompleteRoutine, &Event, TRUE, TRUE, TRUE);

					IoCallDriver(DeviceObject, Irp);

					KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, NULL);

					Status = STATUS_SUCCESS;
				}
			}
			ObDereferenceObject(FileObject);
		}
		ZwClose(FileHandle);
		FileHandle = NULL;
	}

	return Status;
}

NTSTATUS
IrpCompleteRoutine(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	KeSetEvent(Irp->UserEvent, IO_NO_INCREMENT, FALSE);

	IoFreeIrp(Irp);

	return STATUS_MORE_PROCESSING_REQUIRED;
}


VOID
UnloadDriver(IN PDRIVER_OBJECT DriverObject)
{
	return;
}

