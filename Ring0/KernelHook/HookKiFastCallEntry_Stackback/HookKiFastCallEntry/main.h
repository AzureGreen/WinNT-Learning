#ifndef CXX_main_H
#define CXX_main_H

#include <ntifs.h>

#define DEVICE_NAME  L"\\Device\\MyHookKiFastCallEntryDeviceName"
#define LINK_NAME    L"\\??\\MyHookKiFastCallEntryLinkName"

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	PUINT_PTR  Base;        // 服务表基地址
	PUINT32    Count;       // 每个服务调用次数
	UINT32     Limit;		// 服务函数个数 / 结构体对齐
	PUINT8     Number;      // SystemServiceParameterTable
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;


NTKERNELAPI
UCHAR *
PsGetProcessImageFileName(
	__in PEPROCESS Process
);

VOID
PageProtectOn();

VOID
PageProtectOff();

UINT32
SearchHookAddress(IN PUINT8 StartSearchAddress);


VOID
FakeKiFastCallEntry();

VOID
HookKiFastCallEntry(IN UINT32 HookAddress);

NTSTATUS
FakeNtCreateFile(
	__out PHANDLE FileHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__out PIO_STATUS_BLOCK IoStatusBlock,
	__in_opt PLARGE_INTEGER AllocationSize,
	__in ULONG FileAttributes,
	__in ULONG ShareAccess,
	__in ULONG CreateDisposition,
	__in ULONG CreateOptions,
	__in_bcount_opt(EaLength) PVOID EaBuffer,
	__in ULONG EaLength
);

VOID
SetHook();

VOID
StopHook();

VOID
UnloadDriver(IN PDRIVER_OBJECT DriverObject);

#endif // !CXX_main_H
