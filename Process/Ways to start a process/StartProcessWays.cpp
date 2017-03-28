// StartProcessWays.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <strsafe.h>

using namespace std;

void startProcessByCreateProcess(WCHAR *wzFilePath, WCHAR *wzCmdLine);

void startProcessByShell(WCHAR *wzFilePath, WCHAR *wzCmdLine);

void startProcessByWinexe(WCHAR *wzFilePath, WCHAR *wzCmdLine);

int main()
{
	// way 1
	startProcessByCreateProcess(L"C:\\Windows\\System32\\calc.exe", NULL);
	
	// way 2
	//startProcessByShell(L"C:\\Windows\\System32\\calc.exe", NULL);

	// way 3
	//startProcessByWinexe(L"C:\\Windows\\System32\\calc.exe", NULL);


    return 0;
}

// ͨ��CreateProcess��������
void startProcessByCreateProcess(WCHAR *wzFilePath, WCHAR *wzCmdLine)
{
	STARTUPINFO si = { 0 };
	si.cb = sizeof(STARTUPINFO);  // ��ʼ��

	PROCESS_INFORMATION pi = { 0 };

	BOOL bOk = CreateProcess(wzFilePath, wzCmdLine, NULL, NULL, FALSE,
		CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	if (bOk)
	{
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}

}

// ͨ��ShellExecute��������
void startProcessByShell(WCHAR *wzFilePath, WCHAR *wzCmdLine)
{
	SHELLEXECUTEINFO sei = { 0 };

	sei.cbSize = sizeof(SHELLEXECUTEINFO);
	sei.fMask = SEE_MASK_NOCLOSEPROCESS;      // ʹhProcess��÷��صĽ��̾��ֵ
	sei.lpFile = wzFilePath;
	sei.lpParameters = wzCmdLine;
	sei.nShow = SW_NORMAL;

	BOOL bOk = ShellExecuteEx(&sei);
	if (bOk)
	{
		CloseHandle(sei.hProcess);
	}
}

// ͨ��WinExec��������
void startProcessByWinexe(WCHAR *wzFilePath, WCHAR *wzCmdLine)
{
	CHAR szFilePath[MAX_PATH] = { 0 };
	CHAR szCmdLine[MAX_PATH] = { 0 };

	// ˫��ת����
	WideCharToMultiByte(CP_ACP, NULL, wzFilePath, 
		lstrlen(wzFilePath), szFilePath, MAX_PATH, NULL, NULL);

	WideCharToMultiByte(CP_ACP, NULL, wzCmdLine,
		lstrlen(wzCmdLine), szCmdLine, MAX_PATH, NULL, NULL);

	StringCchCatA(szFilePath, MAX_PATH, szCmdLine);

	WinExec(szFilePath, SW_NORMAL);

}