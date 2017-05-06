#include "main.h"

PVOID                      g_ImageBuffer = NULL;       // �����ں˵Ļ���ַ
PDRIVER_OBJECT             g_DriverObject = NULL;
PLDR_DATA_TABLE_ENTRY      g_PsLoadedModuleList = NULL;
PKSERVICE_TABLE_DESCRIPTOR g_CurrentSsdtAddress = NULL;  // ��ǰϵͳ�����ŵ�Ntos��Ssdt����ַ
PKSERVICE_TABLE_DESCRIPTOR g_ReloadSsdtAddress = NULL;   // �������س�����Ntos��Ssdt����ַ
UINT_PTR                   g_OriginalSsdtFunctionAddress[0x200] = { 0 };   // SsdtFunctionԭ���ĵ�ַ
UINT32                     g_SsdtItem[0x200] = { 0 };                       // Ssdt������ԭʼ��ŵ�����
WCHAR                      g_SsdtFunctionName[0x200][100] = { 0 };          // Ssdt�������Ʊ�����Ŵ�ţ�


NTSTATUS
DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegisterPath)
{
	NTSTATUS       Status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = NULL;

	UNICODE_STRING uniDeviceName = { 0 };
	UNICODE_STRING uniLinkName = { 0 };

	RtlInitUnicodeString(&uniDeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&uniLinkName, LINK_NAME);

	// �����豸����
	Status = IoCreateDevice(DriverObject, 0, &uniDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (NT_SUCCESS(Status))
	{
		// �����豸������
		Status = IoCreateSymbolicLink(&uniLinkName, &uniDeviceName);
		
		DriverObject->DriverUnload = UnloadDriver;

		g_DriverObject = DriverObject;

		EnumSsdtHook();

	}
	else
	{
		DbgPrint("Create Device Object Failed\r\n");
	}

	return Status;
}


/************************************************************************
*  Name : GetNtosExportVariableAddress
*  Param: wzVariableName		Ŀ���������   ��˫�֣�
*  Param: VariableAddress		Ŀ�������ַ ��OUT��
*  Ret  : BOOLEAN
*  ͨ��ȫ�ֱ�����������ַ�����Ʒ���Ntos��������ȫ�ֱ�����������ַ����ַ���������� x86�»��SSDT��ַ
************************************************************************/
BOOLEAN
GetNtosExportVariableAddress(IN const WCHAR *wzVariableName, OUT PVOID *VariableAddress)
{
	UNICODE_STRING	uniVariableName = { 0 };

	if (wzVariableName && wcslen(wzVariableName) > 0)
	{
		RtlInitUnicodeString(&uniVariableName, wzVariableName);

		//��Ntoskrnlģ��ĵ������л��һ�����������ĵ�ַ
		*VariableAddress = MmGetSystemRoutineAddress(&uniVariableName);		// ��������ֵ��PVOID���Ų����˶�άָ��
	}

	if (*VariableAddress == NULL)
	{
		return FALSE;
	}

	return TRUE;
}



/************************************************************************
*  Name : GetCurrentSsdtAddress
*  Param: void
*  Ret  : UINT_PTR
*  ���SSDT��ַ ��x86 ����������/x64 Ӳ���룬��ƫ�ƣ�
************************************************************************/
UINT_PTR
GetCurrentSsdtAddress()
{
	if (g_CurrentSsdtAddress == NULL)
	{
#ifdef _WIN64
		/*
		kd> rdmsr c0000082
		msr[c0000082] = fffff800`03e81640
		*/
		PUINT8	StartSearchAddress = (PUINT8)__readmsr(0xC0000082);   // fffff800`03ecf640
		PUINT8	EndSearchAddress = StartSearchAddress + 0x500;
		PUINT8	i = NULL;
		UINT8   v1 = 0, v2 = 0, v3 = 0;
		INT32   iOffset = 0;    // 002320c7 ƫ�Ʋ��ᳬ��4�ֽ�

		for (i = StartSearchAddress; i<EndSearchAddress; i++)
		{
			/*
			kd> u fffff800`03e81640 l 500
			nt!KiSystemCall64:
			fffff800`03e81640 0f01f8          swapgs
			......

			nt!KiSystemServiceRepeat:
			fffff800`03e9c772 4c8d15c7202300  lea     r10,[nt!KeServiceDescriptorTable (fffff800`040ce840)]
			fffff800`03e9c779 4c8d1d00212300  lea     r11,[nt!KeServiceDescriptorTableShadow (fffff800`040ce880)]
			fffff800`03e9c780 f7830001000080000000 test dword ptr [rbx+100h],80h

			TargetAddress = CurrentAddress + Offset + 7
			fffff800`040ce840 = fffff800`03e9c772 + 0x002320c7 + 7
			*/

			if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
			{
				v1 = *i;
				v2 = *(i + 1);
				v3 = *(i + 2);
				if (v1 == 0x4c && v2 == 0x8d && v3 == 0x15)		// Ӳ����  lea r10
				{
					RtlCopyMemory(&iOffset, i + 3, 4);
					(UINT_PTR)g_CurrentSsdtAddress = (UINT_PTR)(iOffset + (UINT64)i + 7);
				}
			}
		}

#else

		/*
		kd> dd KeServiceDescriptorTable
		80553fa0  80502b8c 00000000 0000011c 80503000
		*/

		// ��Ntoskrnl.exe�ĵ������У���ȡ��KeServiceDescriptorTable��ַ
		GetNtosExportVariableAddress(L"KeServiceDescriptorTable", (PVOID*)&g_CurrentSsdtAddress);

#endif
	}

	DbgPrint("SSDTAddress is %p\r\n", g_CurrentSsdtAddress);

	return (UINT_PTR)g_CurrentSsdtAddress;
}


/************************************************************************
*  Name : APMappingFileInKernelSpace
*  Param: wzFileFullPath		�ļ�����·��
*  Param: MappingBaseAddress	ӳ���Ļ���ַ (OUT)
*  Ret  : BOOLEAN
*  ��PE�ļ�ӳ�䵽�ں˿ռ�
************************************************************************/
NTSTATUS
MappingFileInKernelSpace(IN WCHAR* wzFileFullPath, OUT PVOID* MappingBaseAddress)
{
	NTSTATUS  Status = STATUS_UNSUCCESSFUL;

	if (wzFileFullPath && MappingBaseAddress)
	{
		UNICODE_STRING    uniFileFullPath = { 0 };
		OBJECT_ATTRIBUTES oa = { 0 };
		IO_STATUS_BLOCK   Iosb = { 0 };
		HANDLE			  FileHandle = NULL;
		HANDLE			  SectionHandle = NULL;

		RtlInitUnicodeString(&uniFileFullPath, wzFileFullPath);		// ����ָ���ʽ����unicode
		InitializeObjectAttributes(&oa,									// ��ʼ�� oa
			&uniFileFullPath,											// Dll����·��
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,					// �����ִ�Сд | �ں˾��
			NULL,
			NULL);

		Status = IoCreateFile(&FileHandle,								// ����ļ����
			GENERIC_READ | SYNCHRONIZE,									// ͬ����
			&oa,														// �ļ�����·��
			&Iosb,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0,
			CreateFileTypeNone,
			NULL,
			IO_NO_PARAMETER_CHECKING);

		if (NT_SUCCESS(Status))
		{
			InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

			Status = ZwCreateSection(&SectionHandle,			// �����ڶ���,���ں����ļ�ӳ�� ��CreateFileMapping��
				SECTION_QUERY | SECTION_MAP_READ,
				&oa,
				NULL,
				PAGE_WRITECOPY,
				SEC_IMAGE,              // �ڴ����
				FileHandle);

			if (NT_SUCCESS(Status))
			{
				SIZE_T MappingViewSize = 0;

				Status = ZwMapViewOfSection(SectionHandle,
					ZwCurrentProcess(),				// ӳ�䵽��ǰ���̵��ڴ�ռ��� System
					MappingBaseAddress,
					0,
					0,
					0,
					&MappingViewSize,
					ViewUnmap,
					0,
					PAGE_WRITECOPY);

				ZwClose(SectionHandle);
			}
			ZwClose(FileHandle);
		}
	}

	return Status;
}


/************************************************************************
*  Name : CharToWchar
*  Param: szString		        �����ַ���
*  Param: wzString		        ˫���ַ���
*  Ret  : VOID
*  ����ת˫��
************************************************************************/
VOID
CharToWchar(IN CHAR* szString, OUT WCHAR* wzString)
{
	if (szString && wzString)
	{
		NTSTATUS          Status = STATUS_UNSUCCESSFUL;
		ANSI_STRING       ansiString = { 0 };
		UNICODE_STRING    uniString = { 0 };

		// ����ת˫��
		RtlInitAnsiString(&ansiString, szString);
		Status = RtlAnsiStringToUnicodeString(&uniString, &ansiString, TRUE);
		if (NT_SUCCESS(Status))
		{
			RtlCopyMemory(wzString, uniString.Buffer, uniString.Length);
			RtlFreeUnicodeString(&uniString);
		}
	}
}


NTSTATUS
InitializeSsdtFunctionName()
{
	NTSTATUS  Status = STATUS_SUCCESS;

	PKSERVICE_TABLE_DESCRIPTOR CurrentSsdtAddress = (PKSERVICE_TABLE_DESCRIPTOR)GetCurrentSsdtAddress();
	if (CurrentSsdtAddress == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	if (*g_SsdtFunctionName[0] == 0 || *g_SsdtFunctionName[CurrentSsdtAddress->Limit] == 0)
	{
		UINT32    Count = 0;

#ifdef _WIN64

		/* Win7 64bit
		004> u zwopenprocess
		ntdll!ZwOpenProcess:
		00000000`774c1570 4c8bd1          mov     r10,rcx
		00000000`774c1573 b823000000      mov     eax,23h
		00000000`774c1578 0f05            syscall
		00000000`774c157a c3              ret
		00000000`774c157b 0f1f440000      nop     dword ptr [rax+rax]
		*/

		UINT32    SsdtFunctionIndexOffset = 4;

#else

		/* 	Win7 32bit
		kd> u zwopenProcess
		nt!ZwOpenProcess:
		83e9162c b8be000000      mov     eax,0BEh
		83e91631 8d542404        lea     edx,[esp+4]
		83e91635 9c              pushfd
		83e91636 6a08            push    8
		83e91638 e8b1190000      call    nt!KiSystemService (83e92fee)
		83e9163d c21000          ret     10h
		*/

		UINT32    SsdtFunctionIndexOffset = 1;

#endif

		// 1.ӳ��ntdll���ڴ���
		WCHAR   wzFileFullPath[] = L"\\SystemRoot\\System32\\ntdll.dll";
		PVOID   MappingBaseAddress = NULL;

		Status = MappingFileInKernelSpace(wzFileFullPath, &MappingBaseAddress);
		if (NT_SUCCESS(Status))
		{
			// 2.��ȡntdll�ĵ�����

			PIMAGE_DOS_HEADER       DosHeader = NULL;
			PIMAGE_NT_HEADERS       NtHeader = NULL;

			__try
			{
				DosHeader = (PIMAGE_DOS_HEADER)MappingBaseAddress;
				NtHeader = (PIMAGE_NT_HEADERS)((UINT_PTR)MappingBaseAddress + DosHeader->e_lfanew);
				if (NtHeader && NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
				{
					PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
					PUINT32                 AddressOfFunctions = NULL;      // offset
					PUINT32                 AddressOfNames = NULL;          // offset
					PUINT16                 AddressOfNameOrdinals = NULL;   // Ordinal

					ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)MappingBaseAddress + 
						NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);		// �������ַ

					AddressOfFunctions = (PUINT32)((PUINT8)MappingBaseAddress + ExportDirectory->AddressOfFunctions);
					AddressOfNames = (PUINT32)((PUINT8)MappingBaseAddress + ExportDirectory->AddressOfNames);
					AddressOfNameOrdinals = (PUINT16)((PUINT8)MappingBaseAddress + ExportDirectory->AddressOfNameOrdinals);

					// ���ﲻ����ת����ntdllӦ�ò�����ת��
					for (UINT32 i = 0; i < ExportDirectory->NumberOfNames; i++)
					{
						CHAR*                   szFunctionName = NULL;

						szFunctionName = (CHAR*)((PUINT8)MappingBaseAddress + AddressOfNames[i]);   // ��ú�������

																									// ͨ���������ƿ�ͷ�� ZW ���ж��Ƿ���Ssdt����
						if (szFunctionName[0] == 'Z' && szFunctionName[1] == 'w')
						{
							UINT32   FunctionOrdinal = 0;
							UINT_PTR FunctionAddress = 0;
							INT32    SsdtFunctionIndex = 0;
							WCHAR    wzFunctionName[100] = { 0 };

							FunctionOrdinal = AddressOfNameOrdinals[i];
							FunctionAddress = (UINT_PTR)((PUINT8)MappingBaseAddress + AddressOfFunctions[FunctionOrdinal]);

							SsdtFunctionIndex = *(PUINT32)(FunctionAddress + SsdtFunctionIndexOffset);

							if ((SsdtFunctionIndex >= 0) && (SsdtFunctionIndex < (INT32)CurrentSsdtAddress->Limit))
							{
								CharToWchar(szFunctionName, wzFunctionName);

								wzFunctionName[0] = 'N';
								wzFunctionName[1] = 't';

								RtlStringCchCopyW(g_SsdtFunctionName[SsdtFunctionIndex], wcslen(wzFunctionName) + 1, wzFunctionName);

								Status = STATUS_SUCCESS;
							}

							Count++;
						}
					}
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("Catch Exception\r\n");
			}

			ZwUnmapViewOfSection(NtCurrentProcess(), MappingBaseAddress);
		}
	}

	return Status;
}


/************************************************************************
*  Name : KeGetFileBuffer
*  Param: uniFilePath			�ļ�·�� ��PUNICODE_STRING��
*  Ret  : PVOID                 ��ȡ�ļ����ڴ���׵�ַ
*  ��ȡ�ļ����ڴ�
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

		// �ļ�����
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
*  Param: szModuleName			ģ������ ��PCHAR��
*  Ret  : PVOID                 ģ�����ڴ����׵�ַ
*  ͨ������Ldrö��ģ��
************************************************************************/
PVOID
KeGetModuleHandle(IN PCHAR szModuleName)
{
	ANSI_STRING       ansiModuleName = { 0 };
	WCHAR             Buffer[256] = { 0 };
	UNICODE_STRING    uniModuleName = { 0 };

	// ����ת˫��
	RtlInitAnsiString(&ansiModuleName, szModuleName);
	RtlInitEmptyUnicodeString(&uniModuleName, Buffer, sizeof(Buffer));
	RtlAnsiStringToUnicodeString(&uniModuleName, &ansiModuleName, FALSE);

	for (PLIST_ENTRY TravelListEntry = g_PsLoadedModuleList->InLoadOrderLinks.Flink;
		TravelListEntry != (PLIST_ENTRY)g_PsLoadedModuleList;
		TravelListEntry = TravelListEntry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)TravelListEntry;   // �׳�Ա����InLoadOrderLinks

		if (_wcsicmp(uniModuleName.Buffer, LdrDataTableEntry->BaseDllName.Buffer) == 0)
		{
			DbgPrint("ģ�����ƣ�%S\r\n", LdrDataTableEntry->BaseDllName.Buffer);
			DbgPrint("ģ���ַ��%p\r\n", LdrDataTableEntry->DllBase);
			return LdrDataTableEntry->DllBase;
		}
	}

	return NULL;
}

/************************************************************************
*  Name : KeGetProcAddress
*  Param: ModuleBase			����ģ�����ַ ��PVOID��
*  Param: szFunctionName		������������   ��PCHAR��
*  Ret  : PVOID                 ����������ַ
*  ��õ���������ַ������ת����
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

		// ����ŵ���        
		if ((UINT_PTR)szFunctionName <= 0xffff)
		{
			Ordinal = (UINT16)(i);		// ��ŵ����������õ��ľ������
		}
		else if ((UINT_PTR)(szFunctionName) > 0xffff && i < ExportDirectory->NumberOfNames)       // ���Ƶ����Ķ��ǵ�ַ���϶���0xffff��,���ҿ��Կ������Ƶ�������ŵ���֮ǰ
		{
			Name = (PCHAR)((PUINT8)ModuleBase + AddressOfNames[i]);
			Ordinal = (UINT16)(AddressOfNameOrdinals[i]);		// ���Ƶ������еõ����Ƶ������������ 2�ֽ�
		}
		else
		{
			return 0;
		}

		if (((UINT_PTR)(szFunctionName) <= 0xffff && (UINT16)((UINT_PTR)szFunctionName) == (Ordinal + ExportDirectory->Base)) ||
			((UINT_PTR)(szFunctionName) > 0xffff && _stricmp(Name, szFunctionName) == 0))
		{
			// Ŀǰ��������ŵ����������Ƶ������ǶԵĽ�����
			UINT_PTR FunctionAddress = (UINT_PTR)((PUINT8)ModuleBase + AddressOfFunctions[Ordinal]);		// �õ������ĵ�ַ��Ҳ������ʵ��ַ��

																											// ����ǲ���forwarder export������յõ��ĺ�����ַ���ڵ�����Χ�ڣ����漰��ת��������dll���븸dll�����ĺ������ٵ���----> ת������																						
																											// ��Ϊ����Ǻ�����ʵ��ַ�����Ѿ������˵������ַ��Χ
			if (FunctionAddress >= (UINT_PTR)((PUINT8)ModuleBase + ExportDirectoryRVA) &&
				FunctionAddress <= (UINT_PTR)((PUINT8)ModuleBase + ExportDirectoryRVA + ExportDirectorySize))
			{
				CHAR  szForwarderModuleName[100] = { 0 };
				CHAR  szForwarderFunctionName[100] = { 0 };
				PCHAR Pos = NULL;
				PVOID ForwarderModuleBase = NULL;

				RtlCopyMemory(szForwarderModuleName, (CHAR*)FunctionAddress, strlen((CHAR*)FunctionAddress) + 1);  // ģ������.������������

				Pos = strchr(szForwarderModuleName, '.');		// �ж��ַ��������غ��沿��
				if (!Pos)
				{
					return (PVOID)FunctionAddress;
				}
				*Pos = 0;
				RtlCopyMemory(szForwarderFunctionName, Pos + 1, strlen(Pos + 1) + 1);

				RtlStringCchCopyA(szForwarderModuleName, strlen(".dll") + 1, ".dll");

				ForwarderModuleBase = KeGetModuleHandle(szForwarderModuleName);
				if (ForwarderModuleBase == NULL)
				{
					return (PVOID)FunctionAddress;
				}
				return KeGetProcAddress(ForwarderModuleBase, szForwarderFunctionName);
			}
			// ���� Forward Export ��ֱ��break�˳�forѭ�������� ����������Ϣ��ֻ�к�����ַ
			return (PVOID)FunctionAddress;
		}
	}
	return NULL;
}

/************************************************************************
*  Name : FixImportAddressTable
*  Param: ImageBase			    ��ģ����ػ���ַ ��PVOID��
*  Ret  : VOID
*  ���������  IAT ��亯����ַ
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
		PCHAR szImportModuleName = (PCHAR)((PUINT8)ImageBase + ImportDescriptor->Name);        // ����ģ��
		PVOID ImportModuleBase = KeGetModuleHandle(szImportModuleName);    // ����List�ҵ�����ģ���ַ

		if (ImportModuleBase)
		{
			PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((PUINT8)ImageBase + ImportDescriptor->FirstThunk);
			PIMAGE_THUNK_DATA OriginalFirstThunk = (PIMAGE_THUNK_DATA)((PUINT8)ImageBase + ImportDescriptor->OriginalFirstThunk);

			// �������뺯�����Ʊ�
			for (UINT32 i = 0; OriginalFirstThunk->u1.AddressOfData; i++)
			{
				// ���ں�ģ���У������������ŵ���
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
				// û����ŵ���
				OriginalFirstThunk++;
			}
		}
		else
		{
			DbgPrint("FixImportAddressTable::No Such Module\r\n");
		}

		ImportDescriptor++;    // ��һ�ŵ����
	}
}


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
/************************************************************************
*  Name : FixRelocBaseTable
*  Param: ReloadBase		    ��ģ����ػ���ַ ��PVOID��
*  Param: OriginalBase		    ԭģ����ػ���ַ ��PVOID��
*  Ret  : VOID
*  �����ض����
************************************************************************/
VOID
FixRelocBaseTable(IN PVOID ReloadBase, IN PVOID OriginalBase)
{
	PIMAGE_DOS_HEADER         DosHeader = (PIMAGE_DOS_HEADER)ReloadBase;
	PIMAGE_NT_HEADERS         NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)ReloadBase + DosHeader->e_lfanew);
	PIMAGE_BASE_RELOCATION    BaseRelocation = (PIMAGE_BASE_RELOCATION)((PUINT8)ReloadBase +
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	if (BaseRelocation)
	{
		while (BaseRelocation->SizeOfBlock)
		{
			PUINT16	TypeOffset = (PUINT16)((PUINT8)BaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
			// ������Ҫ�������ض���λ�����Ŀ
			UINT32	NumberOfRelocations = (BaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(UINT16);

			for (UINT32 i = 0; i < NumberOfRelocations; i++)
			{
				if ((TypeOffset[i] >> 12) == IMAGE_REL_BASED_DIR64)
				{
#ifdef _WIN64
					// ���Է��� Win7 x64��ȫ�ֱ���û���ܹ��޸��ɹ�
					PUINT64	RelocAddress = (PUINT64)((PUINT8)ReloadBase + BaseRelocation->VirtualAddress + (TypeOffset[i] & 0x0FFF));  // ��λ���ض����
					*RelocAddress = (UINT64)(*RelocAddress + (UINT_PTR)((UINT_PTR)OriginalBase - (UINT_PTR)NtHeader->OptionalHeader.ImageBase));            // �ض��������� + ����ʵ���ص�ַ - Ԥ���ص�ַ = Offset��

																																							//DbgPrint("RelocAddress: %p\r\n", RelocAddress);
#endif // _WIN64
				}
				else if ((TypeOffset[i] >> 12) == IMAGE_REL_BASED_HIGHLOW)
				{
#ifndef _WIN64
					PUINT32	RelocAddress = (PUINT32)((PUINT8)ReloadBase + BaseRelocation->VirtualAddress + (TypeOffset[i] & 0x0FFF));
					*RelocAddress = (UINT32)(*RelocAddress + ((PUINT8)OriginalBase - NtHeader->OptionalHeader.ImageBase));

					//DbgPrint("RelocAddress: %p\r\n", RelocAddress);
#endif // !_WIN64
				}
			}
			// ת����һ���ض����
			BaseRelocation = (PIMAGE_BASE_RELOCATION)((UINT_PTR)BaseRelocation + BaseRelocation->SizeOfBlock);
		}
	}
	else
	{
		DbgPrint("FixRelocBaseTable::No BaseReloc\r\n");
	}
}


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
/************************************************************************
*  Name : FixKiServiceTable
*  Param: ImageBase			    ��ģ����ػ���ַ ��PVOID��
*  Param: OriginalBase		    ԭģ����ػ���ַ ��PVOID��
*  Ret  : VOID
*  ����SSDT base �Լ�base����ĺ���
************************************************************************/
VOID
FixKiServiceTable(IN PVOID ImageBase, IN PVOID OriginalBase)
{
	UINT_PTR KrnlOffset = (INT64)((UINT_PTR)ImageBase - (UINT_PTR)OriginalBase);

	DbgPrint("Krnl Offset :%x\r\n", KrnlOffset);

	g_ReloadSsdtAddress = (PKSERVICE_TABLE_DESCRIPTOR)((UINT_PTR)g_CurrentSsdtAddress + KrnlOffset);
	if (g_ReloadSsdtAddress &&MmIsAddressValid(g_ReloadSsdtAddress))
	{
		// ��SSDT��ֵ
		g_ReloadSsdtAddress->Base = (PUINT_PTR)((UINT_PTR)(g_CurrentSsdtAddress->Base) + KrnlOffset);
		g_ReloadSsdtAddress->Limit = g_CurrentSsdtAddress->Limit;
		g_ReloadSsdtAddress->Number = g_CurrentSsdtAddress->Number;

		DbgPrint("New KeServiceDescriptorTable:%p\r\n", g_ReloadSsdtAddress);
		DbgPrint("New KeServiceDescriptorTable Base:%p\r\n", g_ReloadSsdtAddress->Base);

		// ��Base���ÿ����Ա��ֵ��������ַ��
		if (MmIsAddressValid(g_ReloadSsdtAddress->Base))
		{

#ifdef _WIN64

			// �տ�ʼ������Ǻ�������ʵ��ַ�����Ǳ������Լ���ȫ��������
			for (UINT32 i = 0; i < g_ReloadSsdtAddress->Limit; i++)
			{
				g_OriginalSsdtFunctionAddress[i] = *(UINT64*)((ULONG_PTR)g_ReloadSsdtAddress->Base + i * 8);
			}

			for (UINT32 i = 0; i < g_ReloadSsdtAddress->Limit; i++)
			{
				UINT32 Temp = 0;
				Temp = (UINT32)(g_OriginalSsdtFunctionAddress[i] - (UINT64)g_CurrentSsdtAddress->Base);
				Temp += ((UINT64)g_CurrentSsdtAddress->Base & 0xffffffff);
				// ����Ssdt->base�еĳ�ԱΪ�����Base��ƫ��
				*(UINT32*)((UINT64)g_ReloadSsdtAddress->Base + i * 4) = (Temp - ((UINT64)g_CurrentSsdtAddress->Base & 0xffffffff)) << 4;
			}

			DbgPrint("CurrentSsdt%p\n", g_CurrentSsdtAddress->Base);
			DbgPrint("ReloaddSsdt%p\n", g_ReloadSsdtAddress->Base);

			for (UINT32 i = 0; i < g_ReloadSsdtAddress->Limit; i++)
			{
				g_SsdtItem[i] = *(UINT32*)((UINT64)g_ReloadSsdtAddress->Base + i * 4);
			}
#else
			for (UINT32 i = 0; i < g_ReloadSsdtAddress->Limit; i++)
			{
				g_OriginalSsdtFunctionAddress[i] = *(UINT32*)((UINT32)g_ReloadSsdtAddress->Base + i * 4);
				g_SsdtItem[i] = g_OriginalSsdtFunctionAddress[i];
				*(UINT32*)((UINT32)g_ReloadSsdtAddress->Base + i * 4) += KrnlOffset;      // ������Ssdt������ַת�������¼��ص��ڴ��еĵ�ַ
			}
#endif // _WIN64

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
*  �����ں˵�һģ��
************************************************************************/
NTSTATUS
ReloadNtkrnl()
{
	NTSTATUS    Status = STATUS_SUCCESS;

	if (g_ImageBuffer == NULL)
	{
		PLDR_DATA_TABLE_ENTRY NtLdr = NULL;
		PVOID                 FileBuffer = NULL;

		Status = STATUS_UNSUCCESSFUL;

		// 1.��õ�һģ����Ϣ
		g_PsLoadedModuleList = (PLDR_DATA_TABLE_ENTRY)((PLDR_DATA_TABLE_ENTRY)g_DriverObject->DriverSection)->InLoadOrderLinks.Flink;  // �õ�Ldr�����׵�Ԫ����ͷ�ڵ㣩

		NtLdr = (PLDR_DATA_TABLE_ENTRY)g_PsLoadedModuleList->InLoadOrderLinks.Flink;   // Ntkrnl

		DbgPrint("ģ������:%S\r\n", NtLdr->BaseDllName.Buffer);
		DbgPrint("ģ��·��:%S\r\n", NtLdr->FullDllName.Buffer);
		DbgPrint("ģ���ַ:%p\r\n", NtLdr->DllBase);
		DbgPrint("ģ���С:%x\r\n", NtLdr->SizeOfImage);

		// 2.��ȡ��һģ���ļ����ڴ棬���ڴ�����ʽ���PE��IAT��BaseReloc�޸�
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

						// 2.1.��ʼ��������
						RtlZeroMemory(g_ImageBuffer, NtHeader->OptionalHeader.SizeOfImage);
						// 2.1.1.����ͷ
						RtlCopyMemory(g_ImageBuffer, FileBuffer, NtHeader->OptionalHeader.SizeOfHeaders);
						// 2.1.2.��������
						SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
						for (UINT16 i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
						{
							RtlCopyMemory((PUINT8)g_ImageBuffer + SectionHeader[i].VirtualAddress,
								(PUINT8)FileBuffer + SectionHeader[i].PointerToRawData, SectionHeader[i].SizeOfRawData);
						}

						// 2.2.�޸������ַ��
						FixImportAddressTable(g_ImageBuffer);

						// 2.3.�޸��ض����
						FixRelocBaseTable(g_ImageBuffer, NtLdr->DllBase);

						// 2.4.�޸�SSDT
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

	}

	return Status;
}


/************************************************************************
*  Name : APEnumSsdtHook
*  Param: OutputBuffer            ring3�ڴ�
*  Param: OutputLength
*  Ret  : NTSTATUS
*  ö�ٽ���ģ��
************************************************************************/
NTSTATUS
EnumSsdtHook()
{
	NTSTATUS  Status = STATUS_UNSUCCESSFUL;

	// 1.��õ�ǰ��SSDT
	g_CurrentSsdtAddress = (PKSERVICE_TABLE_DESCRIPTOR)GetCurrentSsdtAddress();
	if (g_CurrentSsdtAddress && MmIsAddressValid(g_CurrentSsdtAddress))
	{
		// 2.��ʼ��Ssdt��������
		Status = InitializeSsdtFunctionName();
		if (NT_SUCCESS(Status))
		{
			// 3.�����ں�SSDT(�õ�ԭ�ȵ�SSDT������ַ����)
			Status = ReloadNtkrnl();
			if (NT_SUCCESS(Status))
			{
				// 4.�Ա�Original&Current
				for (UINT32 i = 0; i < g_CurrentSsdtAddress->Limit; i++)
				{

#ifdef _WIN64
					// 64λ�洢���� ƫ�ƣ���28λ��
					INT32 OriginalOffset = g_SsdtItem[i] >> 4;
					INT32 CurrentOffset = (*(PINT32)((UINT64)g_CurrentSsdtAddress->Base + i * 4)) >> 4;    // ������λ����λ

					UINT64 CurrentSsdtFunctionAddress = (UINT_PTR)((UINT_PTR)g_CurrentSsdtAddress->Base + CurrentOffset);
					UINT64 OriginalSsdtFunctionAddress = g_OriginalSsdtFunctionAddress[i];

#else
					// 32λ�洢���� ���Ե�ַ
					UINT32 CurrentSsdtFunctionAddress = *(UINT32*)((UINT32)g_CurrentSsdtAddress->Base + i * 4);
					UINT32 OriginalSsdtFunctionAddress = g_SsdtItem[i];

#endif // _WIN64
					if (OriginalSsdtFunctionAddress != CurrentSsdtFunctionAddress)
					{
						DbgPrint("Ssdt Function Ordinal:  %d\r\n", i);
						DbgPrint("Ssdt Function Current:  0x%p\r\n", CurrentSsdtFunctionAddress);
						DbgPrint("Ssdt Function Original: 0x%p\r\n", OriginalSsdtFunctionAddress);
						DbgPrint("Ssdt Function Name:     %S\r\n", g_SsdtFunctionName[i]);

					}

				}

			}
			else
			{
				DbgPrint("Reload Ntkrnl & Ssdt Failed\r\n");
			}
		}
		else
		{
			DbgPrint("Initialize Ssdt Function Name Failed\r\n");
		}
	}
	else
	{
		DbgPrint("Get Current Ssdt Failed\r\n");
	}

	return Status;
}



VOID
UnloadDriver(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING  uniLinkName;
	PDEVICE_OBJECT	NextDeviceObject = NULL;
	PDEVICE_OBJECT  CurrentDeviceObject = NULL;
	RtlInitUnicodeString(&uniLinkName, LINK_NAME);

	IoDeleteSymbolicLink(&uniLinkName);		// ɾ��������
	CurrentDeviceObject = DriverObject->DeviceObject;
	while (CurrentDeviceObject != NULL)		// ѭ������ɾ���豸��
	{
		NextDeviceObject = CurrentDeviceObject->NextDevice;
		IoDeleteDevice(CurrentDeviceObject);
		CurrentDeviceObject = NextDeviceObject;
	}

	if (g_ImageBuffer)
	{
		ExFreePool(g_ImageBuffer);
		g_ImageBuffer = NULL;
	}

	DbgPrint("ArkProtect is stopped!!!");
}