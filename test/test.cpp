#include <windows.h>
#include <iostream>
#include <string>
#include <winternl.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <functional>
#pragma comment(lib, "version.lib")  // 加载版本库
#pragma comment(lib, "ntdll.lib")  // 加载版本库

typedef NTSTATUS(WINAPI* NtUserBuildHwndList_t)(
	HDESK hdesk,
	HWND hwndNext,
	BOOL fEnumChildren,
	BOOL RemoveImmersive,//移除沉浸式窗口
	DWORD idThread,
	UINT cHwndMax,
	HWND* phwndFirst,
	PUINT pcHwndNeeded);

auto enum_process_wnd(HANDLE pid) -> HWND* {

	auto hWin32u = LoadLibrary(_T("win32u.dll"));

	std::function<NTSTATUS(HDESK, HWND, BOOL, BOOL, DWORD, UINT, HWND*, PUINT)> enumWnd =
		(NtUserBuildHwndList_t)GetProcAddress(hWin32u, "NtUserBuildHwndList");

	auto hwndArry = new HWND[10];
	UINT needCount = 0;
	auto status = enumWnd(0, 0, true, 0, 0, 10, hwndArry, &needCount);


	if (status!= 0xC0000023) {

		return nullptr;

	}

	delete[] hwndArry;

	//多申请点
	hwndArry = new HWND[needCount + 100];
 	status = enumWnd(0, 0, 0, 0, 0, needCount + 100, hwndArry, &needCount);
	if (!NT_SUCCESS(status)) {

		return nullptr;

	}

	auto targetHwnd = new HWND[needCount];
	memset(targetHwnd, 0, needCount * sizeof HWND);
	int count = 0;
	for (int i = 0; i < needCount; i++) {

		//hwnd->pid
		DWORD _pid,_tid;
		_tid=GetWindowThreadProcessId(hwndArry[i], &_pid);
		printf("tid-> %d pid ->%d\r\n", _tid, _pid);
		if (pid == (HANDLE)_pid) targetHwnd[count++] = hwndArry[i];
	}


	delete[] hwndArry;



	return targetHwnd;


}

typedef NTSTATUS(WINAPI* fnLdrLoadDllFunc)(IN PWSTR, IN PULONG, IN PUNICODE_STRING, OUT PVOID*);

int main() {
	
	auto hNtdll = LoadLibrary(_T("ntdll.dll"));

	fnLdrLoadDllFunc LdrLoadDllFunc = (fnLdrLoadDllFunc)GetProcAddress(hNtdll, "LdrLoadDll");
	PVOID hDll = 0;
	const wchar_t* dllPath = L"C:\\Users\\86131\\Desktop\\Dll1.dll";
	UNICODE_STRING usDllPath = { 0 };
	RtlInitUnicodeString(&usDllPath, dllPath);
	auto status=LdrLoadDllFunc(nullptr,0, &usDllPath,&hDll);


	system("pause");
	return 0;
}
