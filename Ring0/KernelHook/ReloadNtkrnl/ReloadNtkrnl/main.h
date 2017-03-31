#ifndef CXX_main_H
#define CXX_main_H

#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include "NtStructs.h"


#define DEVICE_NAME  L"\\Device\\MyReloadNtkrnlDeviceName"
#define LINK_NAME    L"\\??\\MyReloadNtkrnlLinkName"

#define IA32_SYSENTER_CS  0x174 
#define IA32_SYSENTER_ESP 0x175  
#define IA32_SYSENTER_EIP 0x176  


extern 
PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;

NTKERNELAPI
UCHAR *
PsGetProcessImageFileName(
	__in PEPROCESS Process
);

PVOID
KeGetFileBuffer(IN PUNICODE_STRING uniFilePath);

PVOID
KeGetModuleHandle(IN PCHAR szModuleName);

PVOID
KeGetProcAddress(IN PVOID ModuleBase, IN PCHAR szFunctionName);

VOID
FixImportAddressTable(IN PVOID ImageBase);

VOID
FixRelocBaseTable(IN PVOID ImageBase, IN PVOID OriginalBase);

NTSTATUS
MyNtTerminateProcess(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus);

VOID
FixKiServiceTable(IN PVOID ImageBase, IN PVOID OriginalBase);

NTSTATUS
ReloadNtkrnl();

UINT32
GetKiFastCallEntryAddress();

UINT32
SearchHookAddress(IN PUINT8 StartSearchAddress);

VOID
PageProtectOn();

VOID
PageProtectOff();

UINT32
FilterEntry(IN UINT32 ServiceTableBase, IN UINT32 FunctionIndex, IN UINT32 OriginalFunctionAddress);

VOID
NewKiFastCallEntry();

VOID
HookKiFastCallEntry();


VOID
ResumeKiFastCallEntryHook();

VOID
UnloadDriver(IN PDRIVER_OBJECT DriverObject);


#endif // !CXX_main_H
