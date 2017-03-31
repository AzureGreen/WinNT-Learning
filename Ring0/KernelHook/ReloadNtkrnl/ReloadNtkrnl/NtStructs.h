#ifndef CXX_NtStructs_H
#define CXX_NtStructs_H

#include <ntifs.h>

//////////////////////////////////////////////////////////////////////////
// Ldr
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

//////////////////////////////////////////////////////////////////////////
// SSDT
typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	PUINT_PTR  Base;        // 服务表基地址
	PUINT32    Count;       // 每个服务调用次数
	UINT32     Limit;		// 服务函数个数 / 结构体对齐
	PUINT8     Number;      // SystemServiceParameterTable
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

#endif // !CXX_NtStructs_H
