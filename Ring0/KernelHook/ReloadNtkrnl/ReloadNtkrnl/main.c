#include "main.h"

typedef NTSTATUS
(*pfnNtTerminateProcess)(
	IN HANDLE ProcessHandle,
	IN NTSTATUS ExitStatus
	);


PVOID                      g_ImageBuffer = NULL;
PDRIVER_OBJECT             g_DriverObject = NULL;
PLDR_DATA_TABLE_ENTRY      g_PsLoadedModuleList = NULL;
PKSERVICE_TABLE_DESCRIPTOR g_NewKeServiceDescriptorTable = NULL;
UINT32                     g_HookedAddress = 0; // KiFastCallEntry的Hook点
UINT32                     g_BackOriginalAddress = 0; // 返回KiFastCallEntry的地址

pfnNtTerminateProcess      g_OriginalNtTerminateProcess = NULL;

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegisterPath)
{
	NTSTATUS Status = STATUS_SUCCESS;

	DriverObject->DriverUnload = UnloadDriver;

	g_DriverObject = DriverObject;

	Status = ReloadNtkrnl();     // 重载内核
	if (NT_SUCCESS(Status))
	{
		//UINT32 v1 = 0;
		DbgPrint("ReloadNtkrnl Success\r\n");

		//v1 = GetKiFastCallEntryAddress();

		//DbgPrint("KiFastCallEntry:%p\r\n", v1);

		HookKiFastCallEntry();

	}
	else
	{
		DbgPrint("ReloadNtkrnl Failed\r\n");
	}


	DbgPrint("ReloadNtkrnl Start!!!");

	return Status;
}

/************************************************************************
*  Name : KeGetFileBuffer
*  Param: uniFilePath			文件路径 （PUNICODE_STRING）
*  Ret  : PVOID                 读取文件到内存的首地址
*  读取文件到内存
************************************************************************/
PVOID
KeGetFileBuffer(IN PUNICODE_STRING uniFilePath)
{
	NTSTATUS          Status = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES oa = { 0 };
	HANDLE            FileHandle = NULL;
	IO_STATUS_BLOCK   IoStatusBlock = { 0 };
	PVOID             FileBuffer = NULL;

	InitializeObjectAttributes(&oa, uniFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	Status = ZwCreateFile(&FileHandle,
		FILE_READ_DATA,
		&oa,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (NT_SUCCESS(Status))
	{
		FILE_STANDARD_INFORMATION fsi = { 0 };

		// 文件长度
		Status = ZwQueryInformationFile(FileHandle,
			&IoStatusBlock,
			&fsi,
			sizeof(FILE_STANDARD_INFORMATION),
			FileStandardInformation);
		if (NT_SUCCESS(Status))
		{
			DbgPrint("%d\r\n", IoStatusBlock.Information);
			DbgPrint("%d\r\n", fsi.EndOfFile.LowPart);

			FileBuffer = ExAllocatePool(PagedPool, fsi.EndOfFile.LowPart);
			if (FileBuffer)
			{
				LARGE_INTEGER ReturnLength = { 0 };

				Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, FileBuffer, fsi.EndOfFile.LowPart, &ReturnLength, NULL);
				if (!NT_SUCCESS(Status))
				{
					DbgPrint("KeGetFileData::ZwReadFile Failed\r\n");
				}
			}
			else
			{
				DbgPrint("KeGetFileData::ZwQueryInformationFile Failed\r\n");
			}
		}
		else
		{
			DbgPrint("KeGetFileData::ZwQueryInformationFile Failed\r\n");
		}
		ZwClose(FileHandle);
	}
	else
	{
		DbgPrint("KeGetFileData::ZwCreateFile Failed\r\n");
	}

	return FileBuffer;
}

/************************************************************************
*  Name : KeGetModuleHandle
*  Param: szModuleName			模块名称 （PCHAR）
*  Ret  : PVOID                 模块在内存中首地址
*  通过遍历Ldr枚举模块
************************************************************************/
PVOID
KeGetModuleHandle(IN PCHAR szModuleName)
{
	ANSI_STRING       ansiModuleName = { 0 };
	WCHAR             Buffer[256] = { 0 };
	UNICODE_STRING    uniModuleName = { 0 };

	// 单字转双字
	RtlInitAnsiString(&ansiModuleName, szModuleName);
	RtlInitEmptyUnicodeString(&uniModuleName, Buffer, sizeof(Buffer));
	RtlAnsiStringToUnicodeString(&uniModuleName, &ansiModuleName, FALSE);

	for (PLIST_ENTRY TravelListEntry = g_PsLoadedModuleList->InLoadOrderLinks.Flink;
		TravelListEntry != (PLIST_ENTRY)g_PsLoadedModuleList;
		TravelListEntry = TravelListEntry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)TravelListEntry;   // 首成员就是InLoadOrderLinks

		if (_wcsicmp(uniModuleName.Buffer, LdrDataTableEntry->BaseDllName.Buffer) == 0)
		{
			DbgPrint("模块名称：%S\r\n", LdrDataTableEntry->BaseDllName.Buffer);
			DbgPrint("模块基址：%p\r\n", LdrDataTableEntry->DllBase);
			return LdrDataTableEntry->DllBase;
		}
	}

	return NULL;
}

/************************************************************************
*  Name : KeGetProcAddress
*  Param: ModuleBase			导出模块基地址 （PVOID）
*  Param: szFunctionName		导出函数名称   （PCHAR）
*  Ret  : PVOID                 导出函数地址
*  获得导出函数地址（处理转发）
************************************************************************/
PVOID
KeGetProcAddress(IN PVOID ModuleBase, IN PCHAR szFunctionName)
{
	PIMAGE_DOS_HEADER			DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
	PIMAGE_NT_HEADERS			NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)ModuleBase + DosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY		ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)ModuleBase +
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	UINT32	ExportDirectoryRVA = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	UINT32	ExportDirectorySize = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	PUINT32	AddressOfFunctions = (PUINT32)((PUINT8)ModuleBase + ExportDirectory->AddressOfFunctions);
	PUINT32	AddressOfNames = (PUINT32)((PUINT8)ModuleBase + ExportDirectory->AddressOfNames);
	PUINT16	AddressOfNameOrdinals = (PUINT16)((PUINT8)ModuleBase + ExportDirectory->AddressOfNameOrdinals);


	for (UINT32 i = 0; i < ExportDirectory->NumberOfFunctions; i++)
	{
		UINT16	Ordinal = 0xffff;
		PCHAR	Name = NULL;

		// 按序号导出        
		if ((UINT32)szFunctionName <= 0xffff)
		{
			Ordinal = (UINT16)(i);		// 序号导出函数，得到的就是序号
		}
		else if ((UINT_PTR)(szFunctionName) > 0xffff && i < ExportDirectory->NumberOfNames)       // 名称导出的都是地址，肯定比0xffff大,而且可以看出名称导出在序号导出之前
		{
			Name = (PCHAR)((PUINT8)ModuleBase + AddressOfNames[i]);
			Ordinal = (UINT16)(AddressOfNameOrdinals[i]);		// 名称导出表中得到名称导出函数的序号 2字节
		}
		else
		{
			return 0;
		}

		if (((UINT_PTR)(szFunctionName) <= 0xffff && (UINT16)((UINT_PTR)szFunctionName) == (Ordinal + ExportDirectory->Base)) ||
			((UINT_PTR)(szFunctionName) > 0xffff && _stricmp(Name, szFunctionName) == 0))
		{
			// 目前不论是序号导出还是名称导出都是对的进这里
			UINT_PTR FunctionAddress = (UINT_PTR)((PUINT8)ModuleBase + AddressOfFunctions[Ordinal]);		// 得到函数的地址（也许不是真实地址）

			// 检查是不是forwarder export，如果刚得到的函数地址还在导出表范围内，则涉及到转发器（子dll导入父dll导出的函数后再导出----> 转发器）																						
			// 因为如果是函数真实地址，就已经超出了导出表地址范围
			if (FunctionAddress >= (UINT_PTR)((PUINT8)ModuleBase + ExportDirectoryRVA) &&
				FunctionAddress <= (UINT_PTR)((PUINT8)ModuleBase + ExportDirectoryRVA + ExportDirectorySize))
			{
				CHAR  szForwarderModuleName[100] = { 0 };
				CHAR  szForwarderFunctionName[100] = { 0 };
				PCHAR Pos = NULL;
				PVOID ForwarderModuleBase = NULL;

				RtlCopyMemory(szForwarderModuleName, (CHAR*)FunctionAddress, strlen((CHAR*)FunctionAddress) + 1);  // 模块名称.导出函数名称

				Pos = strchr(szForwarderModuleName, '.');		// 切断字符串，返回后面部分
				if (!Pos)
				{
					return (PVOID)FunctionAddress;
				}
				*Pos = 0;
				RtlCopyMemory(szForwarderFunctionName, Pos + 1, strlen(Pos + 1) + 1);

				RtlStringCchCopyA(szForwarderModuleName, 100, ".dll");

				ForwarderModuleBase = KeGetModuleHandle(szForwarderModuleName);
				if (ForwarderModuleBase == NULL)
				{
					return (PVOID)FunctionAddress;
				}
				return KeGetProcAddress(ForwarderModuleBase, szForwarderFunctionName);
			}
			// 不是 Forward Export 就直接break退出for循环，返回 导出函数信息，只有函数地址
			return (PVOID)FunctionAddress;
		}
	}
	return NULL;
}

/************************************************************************
*  Name : FixImportAddressTable
*  Param: ImageBase			    新模块加载基地址 （PVOID）
*  Ret  : VOID                 
*  修正导入表  IAT 填充函数地址
************************************************************************/
VOID
FixImportAddressTable(IN PVOID ImageBase)
{
	PIMAGE_DOS_HEADER         DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS         NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)ImageBase + DosHeader->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR  ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PUINT8)ImageBase +
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (ImportDescriptor->Characteristics)
	{
		PCHAR szImportModuleName = (PCHAR)((PUINT8)ImageBase + ImportDescriptor->Name);        // 导入模块
		PVOID ImportModuleBase = KeGetModuleHandle(szImportModuleName);    // 遍历List找到导入模块地址

		if (ImportModuleBase)
		{
			PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((PUINT8)ImageBase + ImportDescriptor->FirstThunk);
			PIMAGE_THUNK_DATA OriginalFirstThunk = (PIMAGE_THUNK_DATA)((PUINT8)ImageBase + ImportDescriptor->OriginalFirstThunk);

			// 遍历导入函数名称表
			for (UINT32 i = 0; OriginalFirstThunk->u1.AddressOfData; i++)
			{
				// 在内核模块中，导入表不存在序号导入
				if (!IMAGE_SNAP_BY_ORDINAL(OriginalFirstThunk->u1.Ordinal))
				{
					PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)((PUINT8)ImageBase + OriginalFirstThunk->u1.AddressOfData);
					PVOID                 FunctionAddress = NULL;
					FunctionAddress = KeGetProcAddress(ImportModuleBase, ImportByName->Name);
					if (FunctionAddress)
					{
						FirstThunk[i].u1.Function = (UINT_PTR)FunctionAddress;
					}
					else
					{
						DbgPrint("FixImportAddressTable::No Such Function\r\n");
					}
				}
				// 没有序号导入
				OriginalFirstThunk++;
			}
		}
		else
		{
			DbgPrint("FixImportAddressTable::No Such Module\r\n");
		}
		
		ImportDescriptor++;    // 下一张导入表
	}
}

/************************************************************************
*  Name : FixRelocBaseTable
*  Param: ImageBase			    新模块加载基地址 （PVOID）
*  Param: OriginalBase		    原模块加载基地址 （PVOID）
*  Ret  : VOID                
*  修正重定向表
************************************************************************/
/*
1: kd> u PsLookupProcessByProcessId l 10
nt!PsLookupProcessByProcessId:
84061575 8bff            mov     edi,edi
84061577 55              push    ebp
84061578 8bec            mov     ebp,esp
8406157a 83ec0c          sub     esp,0Ch
8406157d 53              push    ebx
8406157e 56              push    esi
8406157f 648b3524010000  mov     esi,dword ptr fs:[124h]
84061586 33db            xor     ebx,ebx
84061588 66ff8e84000000  dec     word ptr [esi+84h]
8406158f 57              push    edi
84061590 ff7508          push    dword ptr [ebp+8]
84061593 8b3d347ff483    mov     edi,dword ptr [nt!PspCidTable (83f47f34)]
84061599 e8d958feff      call    nt!ExMapHandleToPointer (84046e77)
8406159e 8bf8            mov     edi,eax
840615a0 85ff            test    edi,edi
840615a2 747c            je      nt!PsLookupProcessByProcessId+0xab (84061620)
1: kd> u AFE5C575 l 10
afe5c575 8bff            mov     edi,edi
afe5c577 55              push    ebp
afe5c578 8bec            mov     ebp,esp
afe5c57a 83ec0c          sub     esp,0Ch
afe5c57d 53              push    ebx
afe5c57e 56              push    esi
afe5c57f 648b3524010000  mov     esi,dword ptr fs:[124h]
afe5c586 33db            xor     ebx,ebx
afe5c588 66ff8e84000000  dec     word ptr [esi+84h]
afe5c58f 57              push    edi
afe5c590 ff7508          push    dword ptr [ebp+8]
afe5c593 8b3d347ff483    mov     edi,dword ptr [nt!PspCidTable (83f47f34)]
afe5c599 e8d958feff      call    afe41e77
afe5c59e 8bf8            mov     edi,eax
afe5c5a0 85ff            test    edi,edi
afe5c5a2 747c            je      afe5c620
*/
VOID
FixRelocBaseTable(IN PVOID ImageBase, IN PVOID OriginalBase)
{
	PIMAGE_DOS_HEADER         DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS         NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)ImageBase + DosHeader->e_lfanew);
	PIMAGE_BASE_RELOCATION    BaseRelocation = (PIMAGE_BASE_RELOCATION)((PUINT8)ImageBase + 
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	if (BaseRelocation)
	{
		while (BaseRelocation->SizeOfBlock)
		{
			PUINT16	TypeOffset = (PUINT16)((PUINT8)BaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
			// 计算需要修正的重定向位项的数目
			UINT32	NumberOfRelocations = (BaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(UINT16);

			for (UINT32 i = 0; i < NumberOfRelocations; i++)
			{
				if ((TypeOffset[i] >> 12) == IMAGE_REL_BASED_HIGHLOW)
				{
					PUINT32	RelocAddress = (PUINT32)((PUINT8)ImageBase + BaseRelocation->VirtualAddress + (TypeOffset[i] & 0x0FFF));
					*RelocAddress = (UINT32)(*RelocAddress + ((PUINT8)OriginalBase - NtHeader->OptionalHeader.ImageBase));
				}
			}
			BaseRelocation = (PIMAGE_BASE_RELOCATION)((PUINT8)BaseRelocation + BaseRelocation->SizeOfBlock);
		}
	}
	else
	{
		DbgPrint("FixRelocBaseTable::No BaseReloc\r\n");
	}
}

/************************************************************************
*  Name : MyNtTerminateProcess
*  Param: ProcessHandle		    
*  Param: ExitStatus		   
*  Ret  : NTSTATUS
*  过滤NtTerminateProcess系统调用
************************************************************************/
NTSTATUS
MyNtTerminateProcess(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus)
{
	NTSTATUS  Status = STATUS_SUCCESS;
	PEPROCESS EProcess = NULL;

	Status = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, KernelMode, &EProcess, NULL);
	if (NT_SUCCESS(Status))
	{
		if (_stricmp(PsGetProcessImageFileName(EProcess), "calc.exe") == 0)
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
		return g_OriginalNtTerminateProcess(ProcessHandle, ExitStatus);
	}
	else
	{
		return Status;
	}
}
 
/************************************************************************
*  Name : FixKiServiceTable
*  Param: ImageBase			    新模块加载基地址 （PVOID）
*  Param: OriginalBase		    原模块加载基地址 （PVOID）
*  Ret  : VOID
*  修正SSDT base 以及base里面的函数
************************************************************************/
/*
Original
0: kd> dd KeServiceDescriptorTable
83f6f9c0  83e83d9c 00000000 00000191 83e843e4
83f6f9d0  00000000 00000000 00000000 00000000

Before
0: kd> dd AFD6A9C0
afd6a9c0  00000000 00000000 00000000 00000000
afd6a9d0  00000000 00000000 00000000 00000000

After:
1: kd> dd AFD6A9C0
afd6a9c0  afc7ed9c 00000000 00000191 83e843e4
afd6a9d0  00000000 00000000 00000000 00000000

1: kd> dd afc7ed9c
afc7ed9c  afe7ac28 afcc140d afe0ab68 afc2588a
afc7edac  afe7c4ff afcfe3fa afeecb05 afeecb4e

1: kd> u afe7ac28
afe7ac28 8bff            mov     edi,edi
afe7ac2a 55              push    ebp
afe7ac2b 8bec            mov     ebp,esp
afe7ac2d 64a124010000    mov     eax,dword ptr fs:[00000124h]
afe7ac33 66ff8884000000  dec     word ptr [eax+84h]
afe7ac3a 56              push    esi
afe7ac3b 57              push    edi
afe7ac3c 6a01            push    1

*/
VOID
FixKiServiceTable(IN PVOID ImageBase, IN PVOID OriginalBase)
{
	INT32 iKrnlOffset = (INT32)((UINT_PTR)ImageBase - (UINT_PTR)OriginalBase);

	DbgPrint("Krnl Offset :%x\r\n", iKrnlOffset);

	g_NewKeServiceDescriptorTable = (PKSERVICE_TABLE_DESCRIPTOR)((PUINT8)KeServiceDescriptorTable + iKrnlOffset);
	if (MmIsAddressValid(g_NewKeServiceDescriptorTable))
	{
		// 给SSDT赋值
		g_NewKeServiceDescriptorTable->Base = (PUINT_PTR)((PUINT8)(KeServiceDescriptorTable->Base) + iKrnlOffset);
		g_NewKeServiceDescriptorTable->Limit = KeServiceDescriptorTable->Limit;
		g_NewKeServiceDescriptorTable->Number = KeServiceDescriptorTable->Number;

		DbgPrint("New KeServiceDescriptorTable:%p\r\n", g_NewKeServiceDescriptorTable);
		DbgPrint("New KeServiceDescriptorTable Base:%p\r\n", g_NewKeServiceDescriptorTable->Base);

		// 给Base里的每个成员赋值（函数地址）
		if (MmIsAddressValid(g_NewKeServiceDescriptorTable->Base))
		{
			for (UINT32 i = 0; i < g_NewKeServiceDescriptorTable->Limit; i++)
			{
				g_NewKeServiceDescriptorTable->Base[i] += iKrnlOffset;      // 将所有SSDT函数地址转到我们新加载到内存中的地址
			}

			// 此处为了测试，对NtTerminateProcess进行Hook
			g_OriginalNtTerminateProcess = (pfnNtTerminateProcess)g_NewKeServiceDescriptorTable->Base[0x172];
			g_NewKeServiceDescriptorTable->Base[0x172] = (UINT_PTR)MyNtTerminateProcess;

			DbgPrint("Old NtTerminateProcess:%p\r\n", g_OriginalNtTerminateProcess);
			DbgPrint("New NtTerminateProcess Base:%p\r\n", g_NewKeServiceDescriptorTable->Base[0x172]);

		}
		else
		{
			DbgPrint("New KeServiceDescriptorTable Base is not valid\r\n");
		}
	}
	else
	{
		DbgPrint("New KeServiceDescriptorTable is not valid\r\n");
	}
}

/************************************************************************
*  Name : ReloadNtkrnl
*  Param: VOID
*  Ret  : NTSTATUS
*  重载内核第一模块
************************************************************************/
NTSTATUS
ReloadNtkrnl()
{
	NTSTATUS              Status = STATUS_UNSUCCESSFUL;
	PLDR_DATA_TABLE_ENTRY NtLdr = NULL;
	PVOID                 FileBuffer = NULL;

	// 1.获得第一模块信息
	g_PsLoadedModuleList = (PLDR_DATA_TABLE_ENTRY)((PLDR_DATA_TABLE_ENTRY)g_DriverObject->DriverSection)->InLoadOrderLinks.Flink;  // 拿到Ldr链表首单元（空头节点）

	NtLdr = (PLDR_DATA_TABLE_ENTRY)g_PsLoadedModuleList->InLoadOrderLinks.Flink;   // Ntkrnl
	
	DbgPrint("模块名称:%S\r\n", NtLdr->BaseDllName.Buffer);
	DbgPrint("模块路径:%S\r\n", NtLdr->FullDllName.Buffer);
	DbgPrint("模块地址:%p\r\n", NtLdr->DllBase);
	DbgPrint("模块大小:%x\r\n", NtLdr->SizeOfImage);

	// 2.读取第一模块文件到内存，按内存对齐格式完成PE的IAT，BaseReloc修复
	FileBuffer = KeGetFileBuffer(&NtLdr->FullDllName);    
	if (FileBuffer)
	{
		PIMAGE_DOS_HEADER DosHeader = NULL;
		PIMAGE_NT_HEADERS NtHeader = NULL;
		PIMAGE_SECTION_HEADER SectionHeader = NULL;

		DosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
		if (DosHeader->e_magic == IMAGE_DOS_SIGNATURE)
		{
			NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)FileBuffer + DosHeader->e_lfanew);
			if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
			{
				g_ImageBuffer = ExAllocatePool(NonPagedPool, NtHeader->OptionalHeader.SizeOfImage);
				if (g_ImageBuffer)
				{
					DbgPrint("New Base::%p\r\n", g_ImageBuffer);

					// 2.1.开始拷贝数据
					RtlZeroMemory(g_ImageBuffer, NtHeader->OptionalHeader.SizeOfImage);
					// 2.1.1.拷贝头
					RtlCopyMemory(g_ImageBuffer, FileBuffer, NtHeader->OptionalHeader.SizeOfHeaders);
					// 2.1.2.拷贝节区
					SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
					for (UINT16 i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
					{
						RtlCopyMemory((PUINT8)g_ImageBuffer + SectionHeader[i].VirtualAddress,
							(PUINT8)FileBuffer + SectionHeader[i].PointerToRawData, SectionHeader[i].SizeOfRawData);
					}

					// 2.2.修复导入地址表
					FixImportAddressTable(g_ImageBuffer);

					// 2.3.修复重定向表
					FixRelocBaseTable(g_ImageBuffer, NtLdr->DllBase);

					// 2.4.修复SSDT
					FixKiServiceTable(g_ImageBuffer, NtLdr->DllBase);

					Status = STATUS_SUCCESS;
				}
				else
				{
					DbgPrint("ReloadNtkrnl:: Not Valid PE\r\n");
				}
			}
			else
			{
				DbgPrint("ReloadNtkrnl:: Not Valid PE\r\n");
			}
		}
		else
		{
			DbgPrint("ReloadNtkrnl:: Not Valid PE\r\n");
		}
		ExFreePool(FileBuffer);
		FileBuffer = NULL;
	}

	return Status;
}

/************************************************************************
*  Name : GetKiFastCallEntryAddress
*  Param: VOID
*  Ret  : UINT32                    KiFastCallEntry Address
*  通过GDT查找KiFastCallEntry的地址 CS:EIP
************************************************************************/
UINT32
GetKiFastCallEntryAddress()
{
	UINT32 KiFastCallEntryAddress = 0;
	UINT64 GDTR = ~0;
	PUINT64 Pointer = &GDTR;

	__asm
	{
		pushad
		pushfd

		mov ecx, 0x174      // IA32_SYSENTER_CS
		rdmsr
		mov ebx, eax        // Selector   00000000`00000008
		shr ebx, 3          // index      1

		//int 3
		mov ecx, Pointer
		sgdt fword ptr[ecx]
		add ecx, 2           // GDT Base Address Pointer
		mov edx, [ecx]       // GDT Base Address

		/*
		1: kd> dq/c 1 807ddc28
		807ddc28  00cf9b00`0000ffff
		807ddc30  00cf9300`0000ffff

		1: kd> dd 807ddc28
		807ddc28  0000ffff 00cf9b00 0000ffff 00cf9300

		1: kd> db 807ddc28
		807ddc28  ff ff 00 00 00 9b cf 00-ff ff 00 00 00 93 cf 00
		*/

		lea ecx, [edx + ebx * 8]  // 807ddc28

		mov ebx, ecx
		add ebx, 7
		mov edx, [ebx]
		shl edx, 18h	      // 00 ff ff [00] --> [00] 00 00 00 
		mov ebx, ecx
		add ebx, 2
		mov eax, [ebx]
		and eax, 0x00ffffff   // 9b 00 00 00 --> 00 [00 00 00] 
		add edx, eax          // Segment Address

		mov ecx, 0x176        // IA32_SYSENTER_EIP
		rdmsr
		add eax, edx

		mov KiFastCallEntryAddress, eax

		popfd
		popad
	}

	return KiFastCallEntryAddress;
}

/************************************************************************
*  Name : SearchHookAddress
*  Param: StartSearchAddress        搜索起始地址
*  Ret  : UINT32                    Target Hook Address
*  查找合适Hook点地址
************************************************************************/
UINT32
SearchHookAddress(IN PUINT8 StartSearchAddress)
{
	PUINT8	EndSearchAddress = StartSearchAddress + 0x100;

	for (PUINT8 i = StartSearchAddress; i < EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2) &&
			MmIsAddressValid(i + 3) && MmIsAddressValid(i + 4))
		{
			if (*i == 0x2b && *(i + 1) == 0xe1 && *(i + 2) == 0xc1 &&
				*(i + 3) == 0xe9 && *(i + 4) == 0x02)
			{
				/*
				1: kd> rdmsr 0x176
				msr[176] = 00000000`83e7b0c0
				1: kd> u 83e7b0c0
				nt!KiFastCallEntry:
				83e7b0c0 b923000000      mov     ecx,23h
				83e7b0c5 6a30            push    30h
				83e7b0c7 0fa1            pop     fs
				.....
				83e7b199 8b570c          mov     edx,dword ptr [edi+0Ch]
				83e7b19c 8b3f            mov     edi,dword ptr [edi]          // TableBase
				83e7b19e 8a0c10          mov     cl,byte ptr [eax+edx]        
				83e7b1a1 8b1487          mov     edx,dword ptr [edi+eax*4]    // FunctionAddress
				83e7b1a4 2be1            sub     esp,ecx                      // HookedAddress
				83e7b1a6 c1e902          shr     ecx,2
				83e7b1a9 8bfc            mov     edi,esp
				*/

				return (UINT32)i;
			}
		}

	}
	return 0;
}

/************************************************************************
*  Name : PageProtectOn
*  Param: VOID        
*  Ret  : VOID
*  开启页面写保护
************************************************************************/
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

/************************************************************************
*  Name : PageProtectOff
*  Param: VOID
*  Ret  : VOID
*  关闭页面写保护
************************************************************************/
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

/************************************************************************
*  Name : FilterEntry
*  Param: ServiceTableBase             SSDT Base
*  Param: FunctionIndex                函数索引
*  Param: OriginalFunctionAddress      原函数地址
*  Ret  : UINT32                       最后调用函数地址
*  过滤函数
************************************************************************/
UINT32
FilterEntry(IN UINT32 ServiceTableBase, IN UINT32 FunctionIndex, IN UINT32 OriginalFunctionAddress)
{
	if (ServiceTableBase == (UINT32)KeServiceDescriptorTable->Base)
	{
		return g_NewKeServiceDescriptorTable->Base[FunctionIndex];   // 如果是原本的系统调用，则要走进我们的函数
	}
	return OriginalFunctionAddress;
}

/************************************************************************
*  Name : NewKiFastCallEntry
*  Param: VOID
*  Ret  : VOID
*  jmp to FilterEntry
************************************************************************/
__declspec(naked)
VOID
NewKiFastCallEntry()
{
	__asm
	{
		pushad
		pushfd

		push edx            // OriginalFunctionAddress
		push eax            // FunctionIndex
		push edi            // ServiceTableBase
		call FilterEntry

		mov [esp + 0x18], eax

		popfd
		popad

		sub esp, ecx         // to do hooked code
		shr ecx, 2
		jmp g_BackOriginalAddress

	}
}

/************************************************************************
*  Name : NewKiFastCallEntry
*  Param: VOID
*  Ret  : VOID
*  Start to Hook KiFastCallEntry 
************************************************************************/
VOID
HookKiFastCallEntry()
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UINT32   KiFastCallEntry = GetKiFastCallEntryAddress();

	DbgPrint("KiFastCallEntry:%p\r\n", KiFastCallEntry);

	// 1.获得Hook地址
	g_HookedAddress = SearchHookAddress((PUINT8)KiFastCallEntry);
	
	//Status = SearchPattern("\x2B\xE1\xC1\xE9\x02\x8B\xFC", 7, (PUINT8)KiFastCallEntry, 0x50, (PUINT8*)&g_HookedAddress);
	
	if (g_HookedAddress)
	{
		UINT8 JmpCode[5] = { 0 };
		INT32 iOffset = 0;

		JmpCode[0] = 0xe9;
		iOffset = (UINT32)NewKiFastCallEntry - g_HookedAddress - 5;    // TargetAddress = CurrentAddress + Offset + 5  e9
		*(PUINT32)&JmpCode[1] = iOffset;

		g_BackOriginalAddress = g_HookedAddress + 5;   // 保存需要跳回的地址

		// 2.设置hook
		PageProtectOff();
		RtlCopyMemory((PVOID)g_HookedAddress, JmpCode, 5);
		PageProtectOn();
	}
	else
	{
		DbgPrint("Not Find Hook Address\r\n");
	}
}


/************************************************************************
*  Name : ResumeKiFastCallEntryHook
*  Param: VOID
*  Ret  : VOID
*  恢复KiFastCallEntry的Hook
************************************************************************/
VOID
ResumeKiFastCallEntryHook()
{
	/*
	83e7b1a4 2be1            sub     esp,ecx      // HookedAddress
	83e7b1a6 c1e902          shr     ecx,2
	*/

	UINT8 OriginalCode[5] = { 0x2b, 0xe1, 0xc1, 0xe9, 0x02 };

	if (g_HookedAddress)
	{
		PageProtectOff();
		RtlCopyMemory((PVOID)g_HookedAddress, OriginalCode, 5);
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

	ResumeKiFastCallEntryHook();

	if (g_ImageBuffer)
	{
		ExFreePool(g_ImageBuffer);
		g_ImageBuffer = NULL;
	}

	
	DbgPrint("ReloadNtkrnl Is Stopped!!!");
}
