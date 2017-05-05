#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>


#define DEVICE_NAME  L"\\Device\\EnumSsdtHookDeviceName"
#define LINK_NAME    L"\\??\\EnumSsdtHookLinkName"

#define SEC_IMAGE            0x1000000

//////////////////////////////////////////////////////////////////////////
//
// SSDT
//
typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	PUINT_PTR  Base;        // 服务表基地址
	PUINT32    Count;       // 每个服务调用次数
	UINT32     Limit;		// 服务函数个数 / 结构体对齐
	PUINT8     Number;      // SystemServiceParameterTable
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;


//////////////////////////////////////////////////////////////////////////
//
// Ldr
//
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY		InLoadOrderLinks;
	LIST_ENTRY		InMemoryOrderLinks;
	LIST_ENTRY		InInitializationOrderLinks;
	PVOID			DllBase;
	PVOID			EntryPoint;
	UINT32			SizeOfImage;
	UNICODE_STRING  FullDllName;
	UNICODE_STRING  BaseDllName;
	UINT32			Flags;
	UINT16			LoadCount;
	UINT16			TlsIndex;
	LIST_ENTRY		HashLinks;
	UINT32			TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	UINT32 Length;
	UINT8 Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

BOOLEAN 
GetNtosExportVariableAddress(IN const WCHAR * wzVariableName, OUT PVOID * VariableAddress);

UINT_PTR
GetCurrentSsdtAddress();

NTSTATUS
MappingFileInKernelSpace(IN WCHAR * wzFileFullPath, OUT PVOID * MappingBaseAddress);

VOID
CharToWchar(IN CHAR * szString, OUT WCHAR * wzString);

NTSTATUS
InitializeSsdtFunctionName();

PVOID
KeGetFileBuffer(IN PUNICODE_STRING uniFilePath);

PVOID 
KeGetModuleHandle(IN PCHAR szModuleName);

PVOID 
KeGetProcAddress(IN PVOID ModuleBase, IN PCHAR szFunctionName);

VOID 
FixImportAddressTable(IN PVOID ImageBase);

VOID 
FixRelocBaseTable(IN PVOID ReloadBase, IN PVOID OriginalBase);

NTSTATUS 
ReloadNtkrnl();

NTSTATUS 
EnumSsdtHook();

VOID
UnloadDriver(IN PDRIVER_OBJECT DriverObject);


