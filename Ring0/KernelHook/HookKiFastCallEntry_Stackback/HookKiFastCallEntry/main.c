#include "main.h"

typedef NTSTATUS
(*pfnNtCreateFile)(
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

typedef NTSTATUS
(*pfnNtTerminateProcess)(
	IN HANDLE ProcessHandle,
	IN NTSTATUS ExitStatus
	);

extern 
PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;

UINT32 g_OriginalNtCreateFile = 0;         // NTCreateFile 地址
UINT32 g_HookAddress = 0;                  // KiFastCallEntry的Hook点
UINT32 g_BackOriginalAddress = 0;          // 返回KiFastCallEntry的地址
UINT32 g_OriginalFunctionAddress = 0;      // 真正要Hook的函数地址

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegisterPath)
{
	NTSTATUS Status = STATUS_SUCCESS;

	DriverObject->DriverUnload = UnloadDriver;

	SetHook();		// 直接修改进我们的函数

	DbgPrint("HookKiFastCallEntry Start!!!");

	return Status;
}

VOID
PageProtectOn()
{
	__asm
	{
		// 恢复内存保护  
		mov  eax, cr0
		or eax, 10000h
		mov  cr0, eax
		sti
	}
}

VOID
PageProtectOff()
{
	__asm
	{
		// 去掉内存保护
		cli
		mov  eax, cr0
		and  eax, not 10000h
		mov  cr0, eax
	}
}

// 寻找到合适的Hook点
UINT32
SearchHookAddress(IN PUINT8 StartSearchAddress)
{
	PUINT8	EndSearchAddress = StartSearchAddress - 0x100;

	for (PUINT8	i = StartSearchAddress; i > EndSearchAddress; i--)  // 倒着往上面搜索
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2) &&
			MmIsAddressValid(i + 3) && MmIsAddressValid(i + 4))
		{
			/*
			1: kd> rdmsr 0x176
			msr[176] = 00000000`83e7b0c0
			1: kd> u 83e7b0c0
			nt!KiFastCallEntry:
			83e7b0c0 b923000000      mov     ecx,23h
			83e7b0c5 6a30            push    30h
			83e7b0c7 0fa1            pop     fs
			83e7b0c9 8ed9            mov     ds,cx
			83e7b0cb 8ec1            mov     es,cx
			83e7b0cd 648b0d40000000  mov     ecx,dword ptr fs:[40h]
			83e7b0d4 8b6104          mov     esp,dword ptr [ecx+4]
			83e7b0d7 6a23            push    23h
			.....
			83e7b199 8b570c          mov     edx,dword ptr [edi+0Ch]
			83e7b19c 8b3f            mov     edi,dword ptr [edi]
			83e7b19e 8a0c10          mov     cl,byte ptr [eax+edx]
			83e7b1a1 8b1487          mov     edx,dword ptr [edi+eax*4]		// eax Index; edx FunctionAddress; edi Base
			83e7b1a4 2be1            sub     esp,ecx
			83e7b1a6 c1e902          shr     ecx,2
			83e7b1a9 8bfc            mov     edi,esp

			*/

			if (*i == 0x2b && *(i + 1) == 0xe1 && *(i + 2) == 0xc1 &&
				*(i + 3) == 0xe9 && *(i + 4) == 0x02)
			{
				return (UINT32)i;
			}
		}
	}
	return 0;
}


NTSTATUS
FakeNtTerminateProcess(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus)
{
	NTSTATUS  Status = STATUS_SUCCESS;
	PEPROCESS EProcess = NULL;

	Status = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, KernelMode, &EProcess, NULL);
	if (NT_SUCCESS(Status))
	{
		if (_stricmp(PsGetProcessImageFileName(EProcess), "notepad.exe") == 0)
		{
			Status = STATUS_ACCESS_DENIED;
		}
	}

	if (EProcess)
	{
		ObDereferenceObject(EProcess);
	}

	if (NT_SUCCESS(Status))
	{
		return ((pfnNtTerminateProcess)g_OriginalFunctionAddress)(ProcessHandle, ExitStatus);
	}
	else
	{
		return Status;
	}
}


// 过滤函数
UINT32 
FilterEntry(IN UINT32 ServiceTableBase, IN UINT32 FunctionIndex, IN UINT32 OriginalFunctionAddress)
{
	g_OriginalFunctionAddress = OriginalFunctionAddress;

	if (ServiceTableBase == (UINT32)KeServiceDescriptorTable->Base)
	{
		if (FunctionIndex == 0x172)
		{
			PEPROCESS EProcess = PsGetCurrentProcess();

			DbgPrint("%s\r\n", (PUINT8)EProcess + 0x16c);
			
			//return (UINT32)FakeNtTerminateProcess;
		}
	}
	return OriginalFunctionAddress;
}

// jmp to FilterEntry
__declspec(naked)
VOID 
FakeKiFastCallEntry()
{
	__asm
	{
		pushad
		pushfd

		push edx            // OriginalFunctionAddress
		push eax            // FunctionIndex
		push edi            // ServiceTableBase
		call FilterEntry

		popfd
		popad
		
		sub esp, ecx         // to do hooked code
		shr ecx, 2
		jmp g_BackOriginalAddress

	}
}

// Inline Hook, Jmp to fakeKifastcallentry 
VOID
HookKiFastCallEntry(IN UINT32 HookAddress)
{
	UINT8 JmpCode[5] = { 0 };
	INT32 iOffset = 0;

	JmpCode[0] = 0xe9;
	iOffset = (UINT32)FakeKiFastCallEntry - HookAddress - 5;    // TargetAddress = CurrentAddress + Offset + 5  e9
	*(PUINT32)&JmpCode[1] = iOffset;

	PageProtectOff();
	RtlCopyMemory((PVOID)HookAddress, JmpCode, 5);
	PageProtectOn();
}

// 走到这个fakeNT函数里，然后hook掉KiFastCallEntry

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
)
{
	UINT32  ReturnAddress = 0;

	__asm
	{
		pushad
		mov eax, [ebp + 0x4]    // eip stackback
		mov ReturnAddress, eax
		popad
	}

	g_HookAddress = SearchHookAddress((PUINT8)ReturnAddress);
	if (!g_HookAddress)
	{
		DbgPrint("Not Found Suitable Hook Address\r\n");
	}
	
	g_BackOriginalAddress = g_HookAddress + 5;     // 保存需要跳回的地址

	HookKiFastCallEntry(g_HookAddress);    // Hook 设置完毕

	// 恢复SSDT中原函数地址，回去再调用
	PageProtectOff();
	KeServiceDescriptorTable->Base[0x42] = g_OriginalNtCreateFile;
	PageProtectOn();

	return ((pfnNtCreateFile)g_OriginalNtCreateFile)(FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength);

}


VOID
SetHook()
{
	// SSDT Hook 一个常用NTAPI
	g_OriginalNtCreateFile = KeServiceDescriptorTable->Base[0x42];
	PageProtectOff();
	KeServiceDescriptorTable->Base[0x42] = (UINT32)FakeNtCreateFile;
	PageProtectOn();
}


VOID
StopHook()
{
	UINT8 OriginalCode[5] = { 0x2b, 0xe1, 0xc1, 0xe9, 0x02 };

	if (g_HookAddress)
	{
		PageProtectOff();
		RtlCopyMemory((PVOID)g_HookAddress, OriginalCode, 5);
		PageProtectOn();
	}
}


VOID
UnloadDriver(IN PDRIVER_OBJECT DriverObject)
{

	UNICODE_STRING  uniLinkName;
	PDEVICE_OBJECT	NextDeviceObject = NULL;
	PDEVICE_OBJECT  CurrentDeviceObject = NULL;
	RtlInitUnicodeString(&uniLinkName, LINK_NAME);

	IoDeleteSymbolicLink(&uniLinkName);		// 删除链接名
	CurrentDeviceObject = DriverObject->DeviceObject;
	while (CurrentDeviceObject != NULL)		// 循环遍历删除设备链
	{
		NextDeviceObject = CurrentDeviceObject->NextDevice;
		IoDeleteDevice(CurrentDeviceObject);
		CurrentDeviceObject = NextDeviceObject;
	}

	StopHook();

	DbgPrint("HookKiFastCallEntry Is Stopped!!!");
}
