// AddPeSection.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <strsafe.h>
using namespace std;

#define AlignSize(Size, Align) (Size + Align - 1) / Align * Align    // ����

UINT32 RVAToOffset(IN UINT32 RVA, IN PIMAGE_NT_HEADERS NtHeader);

VOID ModifyImportDescriptor(IN PVOID BaseAddress, IN const CHAR *szDllName, IN OPTIONAL const CHAR *szFunctionName = "");

BOOL AddNewSection(IN PVOID BaseAddress, IN const CHAR *szSectionName, IN UINT32 NewSectionSize);

BOOL CanAddNewSection(IN PVOID BaseAddress);

BOOL MappingPEFileInMemory(IN CHAR *szFileFullPath, OUT PVOID *MappingBaseAddress);

VOID UnMappingPEFileInMemory(IN PVOID MappingBaseAddress);

HANDLE g_FileHandle = INVALID_HANDLE_VALUE;
HANDLE g_MappingHandle = NULL;

// �÷����Ǵ��ļ����������ϵ�ע�룬��Դ�ļ����ƻ���
int main()
{
	// ׼�����ʵ�dll·�����ļ�·��
	CHAR szFilePath[MAX_PATH] = { 0 };
	CHAR szDllPath[MAX_PATH] = { 0 };
	CHAR *szImportFuntionName = "InjectFunction";   // ���뺯��Ҳ�Ǳ���ģ�
	GetCurrentDirectoryA(MAX_PATH, szFilePath);
	StringCchCopyA(szDllPath, MAX_PATH, szFilePath);
	StringCchCatA(szFilePath, MAX_PATH, "\\Test.exe");
	StringCchCatA(szDllPath, MAX_PATH, "\\Dll.dll");

	PVOID MappingBase = NULL;

	// ��Ŀ���ļ�ӳ�䵽�ڴ�
	BOOL bOk = MappingPEFileInMemory(szFilePath, &MappingBase);
	if (bOk)
	{
		bOk = CanAddNewSection(MappingBase);
		if (bOk)
		{
			bOk = AddNewSection(MappingBase, ".Inject", 256);
			if (bOk)
			{
				ModifyImportDescriptor(MappingBase, szDllPath, szImportFuntionName);
			}
		}
		else
		{
			printf("Can Not Add New Section\r\n");
		}
		UnMappingPEFileInMemory(MappingBase);
	}
	else
	{
		printf("MappingFile Failed\r\n");
	}

    return 0;
}

/************************************************************************
*  Name : RVAToOffset
*  Param: RVA				�ڴ���ƫ��
*  Param: NtHeader			Ntͷ
*  Ret  : UINT32
*  �ڴ���ƫ��ת�����ļ���ƫ��
************************************************************************/

UINT32 RVAToOffset(IN UINT32 RVA, IN PIMAGE_NT_HEADERS NtHeader)
{
	UINT32					i = 0;
	PIMAGE_SECTION_HEADER	SectionHeader = NULL;

	SectionHeader = IMAGE_FIRST_SECTION(NtHeader);

	if (RVA < SectionHeader[0].PointerToRawData)
	{
		return RVA;
	}

	for (i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
	{
		if (RVA >= SectionHeader[i].VirtualAddress && RVA < (SectionHeader[i].VirtualAddress + SectionHeader[i].SizeOfRawData))
		{
			return (RVA - SectionHeader[i].VirtualAddress + SectionHeader[i].PointerToRawData);
		}
	}

	return 0;
}

/************************************************************************
*  Name : ModifyImportDescriptor
*  Param: BaseAddress				ӳ�����ַ
*  Param: szDllName				    ��̬��·��
*  Param: szFunctionName			������������(OPTIONAL) ����ֻ��Ϊʾ������һ�����������Ը���ʵ��������
*  Ret  : VOID
*  ���������µ��½��У�˳��������ǵ�dll
************************************************************************/

VOID ModifyImportDescriptor(IN PVOID BaseAddress, IN const CHAR *szDllName, IN OPTIONAL const CHAR *szFunctionName/* = ""*/)
{
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)BaseAddress + DosHeader->e_lfanew);

	UINT32 ImportDirectoryRVA = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PUINT8)BaseAddress + RVAToOffset(ImportDirectoryRVA, NtHeader));

	BOOL   bBoundImport = FALSE;
	if (ImportDescriptor->OriginalFirstThunk == 0 && ImportDescriptor->FirstThunk != 0)
	{
		// OriginalFirstThunkΪ0��FirstThunk��Ϊ0������ʹ���˰󶨵��룬���Թرհ󶨵���
		bBoundImport = TRUE;
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
	}

	// �ҵ��Լ���ӵ��½�
	PIMAGE_SECTION_HEADER NewSectionHeader = IMAGE_FIRST_SECTION(NtHeader) + NtHeader->FileHeader.NumberOfSections - 1;
	PUINT8 NewSection = (PUINT8)BaseAddress + NewSectionHeader->PointerToRawData;       // ��λ���Լ������ڴ���½���
	PIMAGE_IMPORT_DESCRIPTOR NewImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)NewSection;

	// ���������
	INT i = 0;
	for (i = 0; ImportDescriptor->FirstThunk != 0 || ImportDescriptor->Characteristics != 0; i++)
	{
		RtlCopyMemory(NewSection + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), ImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		ImportDescriptor++;
		NewImportDescriptor++;
	}

	// �����һ������һ��
	RtlCopyMemory(NewImportDescriptor, (PUINT8)(NewImportDescriptor - 1), sizeof(IMAGE_IMPORT_DESCRIPTOR));

	UINT32 Delta = NewSectionHeader->VirtualAddress - NewSectionHeader->PointerToRawData;    // ����RVA��FOA�Ĳ�ֵ

	// ��� ImportDescriptor->OriginalFirstThunk / FirstThunk
	PIMAGE_THUNK_DATA NewThunk = PIMAGE_THUNK_DATA(NewImportDescriptor + 2);   // ��һ������λ��������ڴ��ַ
	if (bBoundImport)
	{
		((PIMAGE_IMPORT_DESCRIPTOR)NewImportDescriptor)->OriginalFirstThunk = 0;
	}
	else
	{
		((PIMAGE_IMPORT_DESCRIPTOR)NewImportDescriptor)->OriginalFirstThunk = Delta + (UINT_PTR)NewThunk - (UINT_PTR)BaseAddress;
	}
	((PIMAGE_IMPORT_DESCRIPTOR)NewImportDescriptor)->FirstThunk = Delta + (UINT_PTR)NewThunk - (UINT_PTR)BaseAddress;   // RVA
	
	// ��� ImportDescriptor->Name
	PCHAR DllName = (PCHAR)(NewThunk + 2);    // ͬ����һ������λ��������ڴ��ַ
	RtlCopyMemory(DllName, szDllName, strlen(szDllName) + 1);
	DllName[strlen(szDllName)] = '\0';

	((PIMAGE_IMPORT_DESCRIPTOR)NewImportDescriptor)->Name = Delta + (UINT_PTR)DllName - (UINT_PTR)BaseAddress;   // RVA

	// ��� Thunk->u1.AddressOfData
	PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)(DllName + strlen(szDllName) + 1);
	ImportByName->Hint = 1;   // ���
	RtlCopyMemory(ImportByName->Name, szFunctionName, strlen(szFunctionName) + 1);  // ��������
	ImportByName->Name[strlen(szFunctionName) + 1] = '\0';

	NewThunk->u1.AddressOfData = Delta + (UINT_PTR)ImportByName - (UINT_PTR)BaseAddress;
	
	// �޸�ImportTable��λ�ã���λ��NewSection��
	NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = NewSectionHeader->VirtualAddress;
	NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (i + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
}

/************************************************************************
*  Name : AddNewSection
*  Param: BaseAddress			 ӳ�����ַ
*  Param: szSectionName			 �½���������
*  Param: NewSectionSize		 �½����Ĵ�С
*  Ret  : BOOL
*  ���ļ�ĩβ���һ���½�
************************************************************************/

BOOL AddNewSection(IN PVOID BaseAddress, IN const CHAR *szSectionName, IN UINT32 NewSectionSize)
{
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)BaseAddress + DosHeader->e_lfanew);

	// �õ��½ڵ���ʼ��ַ�� ������ʼ��ַ
	PIMAGE_SECTION_HEADER NewSectionHeader = IMAGE_FIRST_SECTION(NtHeader) + NtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER LastSectionHeader = NewSectionHeader - 1;

	UINT32 VirtualSize = AlignSize(NewSectionSize, NtHeader->OptionalHeader.SectionAlignment);
	UINT32 VirtualAddress = AlignSize(LastSectionHeader->VirtualAddress + LastSectionHeader->Misc.VirtualSize, NtHeader->OptionalHeader.SectionAlignment);
	UINT32 SizeOfRawData = AlignSize(NewSectionSize, NtHeader->OptionalHeader.FileAlignment);
	UINT32 PointerToRawData = AlignSize(LastSectionHeader->PointerToRawData + LastSectionHeader->SizeOfRawData, NtHeader->OptionalHeader.FileAlignment);

	// ����½���Ϣ
	RtlCopyMemory(NewSectionHeader->Name, szSectionName, strlen(szSectionName));
	NewSectionHeader->Misc.VirtualSize = VirtualSize;
	NewSectionHeader->VirtualAddress = VirtualAddress;
	NewSectionHeader->SizeOfRawData = SizeOfRawData;
	NewSectionHeader->PointerToRawData = PointerToRawData;
	NewSectionHeader->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;

	// �޸�NtHeader�����Ϣ
	NtHeader->FileHeader.NumberOfSections++;
	NtHeader->OptionalHeader.SizeOfImage += VirtualSize;
	// �رհ󶨵���
	NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
	NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;

	PUINT8 NewSection = (PUINT8)malloc(SizeOfRawData);
	BOOL bOk = FALSE;
	if (NewSection)
	{
		RtlZeroMemory(NewSection, SizeOfRawData);

		SetFilePointer(g_FileHandle, 0, 0, FILE_END);  // ���ļ�ָ���Ƶ����

		DWORD dwReturnLength = 0;
		bOk = WriteFile(g_FileHandle, NewSection, SizeOfRawData, &dwReturnLength, NULL);  // ���ļ�ĩβ׷��һ�οռ�

		free(NewSection);
	}
	return bOk;
}

/************************************************************************
*  Name : CanAddNewSection
*  Param: BaseAddress			 ӳ�����ַ
*  Ret  : BOOL
*  �ж��ļ��Ϸ��ԣ���ͨ���ж��Ƿ��ܹ�����һ���½�
************************************************************************/

BOOL CanAddNewSection(IN PVOID BaseAddress)
{
	// �ж��Ƿ��ǺϷ�PE�ļ�
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)BaseAddress + DosHeader->e_lfanew);
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	// �Ƿ�����ټ���һ������
	if ((NtHeader->FileHeader.NumberOfSections + 1) * sizeof(IMAGE_SECTION_HEADER) >         // ����Section����+1
		NtHeader->OptionalHeader.SizeOfHeaders - ((UINT_PTR)IMAGE_FIRST_SECTION(NtHeader) - (UINT_PTR)BaseAddress))  // ����ͷ��С - ��һ��Section�׵�ַ - PE����ַ = ʣ�¿��Ը��ڵĿռ��С
	{
		return FALSE;
	}
	return TRUE;
}

/************************************************************************
*  Name : MappingPEFileInMemory
*  Param: szFileFullPath			ϵͳ����ģ������
*  Param: MappingBaseAddress		ģ��ӳ�����ַ ��OUT��
*  Param: MappingViewSize			ӳ��ڴ�С ��OUT��
*  Ret  : BOOL
*  ��Ŀ���ļ�ӳ�䵽�ڴ�
************************************************************************/

BOOL MappingPEFileInMemory(IN CHAR *szFileFullPath, OUT PVOID *MappingBaseAddress)
{
	g_FileHandle = CreateFileA(szFileFullPath, GENERIC_READ | GENERIC_WRITE
		, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (g_FileHandle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	UINT32 FileSize = GetFileSize(g_FileHandle, NULL);

	g_MappingHandle = CreateFileMappingA(g_FileHandle, NULL, PAGE_READWRITE, 0, FileSize, NULL);
	if (g_MappingHandle == NULL)
	{
		return FALSE;
	}

	*MappingBaseAddress = MapViewOfFile(g_MappingHandle, FILE_MAP_ALL_ACCESS, 0, 0, FileSize);

	return TRUE;
}

/************************************************************************
*  Name : UnMappingPEFileInMemory
*  Param: MappingBaseAddress		ӳ��ģ�����ַ
*  Ret  : BOOL
*  ���ӳ�䣬������Դ
************************************************************************/

VOID UnMappingPEFileInMemory(IN PVOID MappingBaseAddress)
{
	if (g_MappingHandle)
	{
		CloseHandle(g_MappingHandle);
		g_FileHandle = NULL;
	}
	if (g_FileHandle)
	{
		CloseHandle(g_FileHandle);
		g_MappingHandle = NULL;
	}
	if (MappingBaseAddress != NULL)
	{
		UnmapViewOfFile(MappingBaseAddress);
		MappingBaseAddress = NULL;
	}
}