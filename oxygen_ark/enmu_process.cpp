#include "enmu_process.h"

#pragma comment(lib,"version.lib") 

namespace process{


	auto enum_handles(HANDLE pid) -> phandles_info_t {

		//��ѯ�ʵ��׶��ٸ�
		auto count = 0ul;

		auto b=drv_load::io_ctl(CTL_QUERY_HANDLES_COUNT, &pid, sizeof HANDLE, &count, sizeof(int));
		if (!b) return nullptr;
		
		//�������
		auto ret = new handles_info_t;
		ret->count = count + 10;
		ret->infos = new handle_info_t[ret->count+10];
		//��ѯ�ʾ������Ϣ

		query_handle_t query = { .pid = pid,.infos = ret };
		b = drv_load::io_ctl(CTL_QUERY_HANDLES, &query, sizeof query_handle_t, nullptr, 0);
		if (!b) return nullptr;

		return ret;
	}

	auto force_terminate(HANDLE pid)->bool {

		if (!drv_load::io_ctl(CTL_TERMINATE_PROCESS, (PHANDLE)&pid, sizeof HANDLE, 0,0)) {
			MessageBoxA(nullptr, "failed to terminate process!", "error", MB_OK | MB_ICONERROR);
			return false;
		}
		else {
			MessageBoxA(nullptr, "terminate process successly!", "success", MB_OK | MB_ICONINFORMATION);
			return true;
		}
		
	}

	auto hide_process(HANDLE pid) -> bool {
		if (!drv_load::io_ctl(CTL_HIDE_PROCESS, (PHANDLE)&pid, sizeof HANDLE, 0, 0)) {
			MessageBoxA(nullptr, "failed to hide process!", "error", MB_OK | MB_ICONERROR);
			return false;
		}
		else {
			MessageBoxA(nullptr, "hide process successly!", "success", MB_OK | MB_ICONINFORMATION);
			return true;
		}
		
	}

	auto enum_timers(__in HANDLE pid) -> ptimers_info_t {

		//����HWND 
		auto timersInfo = new timers_info_t;
		unsigned int count = 0;
		//������Ҫqueryһ�� �����ж��ٸ���ʱ��
		if (!drv_load::io_ctl(CTL_QUERY_TIMERS_COUNT, &pid,
			sizeof HANDLE, &count
			, sizeof(unsigned int))) {

			delete timersInfo;
			return nullptr;
		}

	
		timersInfo->infos = new timer_info_t[count+10];//��ż���
		timersInfo->count = count;

		auto query = query_timers_t{ .pid = pid,.timers_info = timersInfo };
		//���ʱ����ʽѯ��
		if (!drv_load::io_ctl(CTL_QUERY_TIMERS, &query,sizeof query_timers_t,0,0)) {

			delete[] timersInfo->infos;
			delete timersInfo;
			return nullptr;
		}

		//ѯ�ʳɹ�
		return timersInfo;

	}


	//ö�ٴ���
	auto enum_windows(HANDLE pid) -> pwindows_info {

		auto hWin32u = LoadLibrary(_T("win32u.dll"));

		std::function<NTSTATUS(HDESK, HWND, BOOL, BOOL, DWORD, UINT, HWND*, PUINT)> enumWnd =
			(NtUserBuildHwndList_t)GetProcAddress(hWin32u, "NtUserBuildHwndList");

		auto hwndArry = new HWND[10];
		UINT needCount = 0;
		auto status = enumWnd(0, 0, true, 0, 0, 10, hwndArry, &needCount);
		

		if (status != 0xC0000023) {

			return nullptr;

		}

		delete[] hwndArry;

		//�������
		hwndArry = new HWND[needCount + 100];
		status = enumWnd(0, 0, true, 0, 0, needCount + 100, hwndArry, &needCount);
		if (!NT_SUCCESS(status)) {

			return nullptr;

		}
		auto winInfos = new windows_info_t;
		winInfos->count = 0;
		winInfos->infos = new window_info_t[needCount];
		memset(winInfos->infos, 0, needCount * sizeof window_info_t);


		for (int i = 0; i < needCount; i++) {
			auto _tid = 0ull, _pid = 0ull;
			_tid = GetWindowThreadProcessId(hwndArry[i], (PDWORD) &_pid);
			if (pid == (HANDLE)_pid) {

	 			winInfos->infos[winInfos->count].hwnd = hwndArry[i];
				winInfos->infos[winInfos->count].pid = pid;
				winInfos->infos[winInfos->count].tid = (HANDLE)_tid;
				GetWindowTextA(hwndArry[i], winInfos->infos[winInfos->count].titile, MAX_PATH);
				winInfos->infos[winInfos->count].isVisible=IsWindowVisible(hwndArry[i]);

				winInfos->count++;
			}
		
		}


		delete[] hwndArry;

		

		return winInfos;

	}

	auto enum_modules(HANDLE pid) -> pmodules_info_t {
		//��ѯ�ʵ����ж��ٸ�ģ��
		UINT64 count = 0;
		bool suc = drv_load::io_ctl(CTL_QUERY_MODULES_COUNT, &pid, sizeof HANDLE, &count, sizeof UINT64);
		if (!suc) return nullptr;

		//�����ڴ�
		pmodules_info_t ret = new modules_info_t;
		ret->pid = pid;
		ret->modules = new module_info_t[count];
		ret->moduleCount = count;

		//ѯ���ڴ�
		suc = drv_load::io_ctl(CTL_QUERY_MODULES, ret, sizeof modules_info_t, 0, 0);
		if (!suc) return nullptr;


		//���ļ����������
		for (int i = 0; i < ret->moduleCount; i++) {
			
			auto companyName = get_file_companyname(ret->modules[i].path);
			if (companyName != nullptr)
				strcpy_s(ret->modules[i].companyName, companyName);
			else memset(ret->modules[i].companyName, 0, MAX_PATH);
		}

		return ret;
	}
	

	auto get_file_companyname(const wchar_t* full_path) -> wchar_t*
	{

		DWORD dwDummy;
		wchar_t* pCompanyName;
		DWORD dwSize = GetFileVersionInfoSizeW(full_path, &dwDummy);
		UINT cbTranslate;

		if (dwSize == 0) {
			return nullptr;
		}



		BYTE* pVersionInfo = new BYTE[dwSize];
		if (!GetFileVersionInfoW(full_path, 0, dwSize, pVersionInfo)) {
			delete[] pVersionInfo;
			return nullptr;
		}


		struct LANGANDCODEPAGE {
			WORD wLanguage;
			WORD wCodePage;
		} *lpTranslate;

		// Read the list of languages and code pages.
		VerQueryValueW(pVersionInfo,
			TEXT("\\VarFileInfo\\Translation"),
			(LPVOID*)&lpTranslate,
			&cbTranslate);

		//��ȡҳ�� ֻ���������ܶ���
		for (int i = 0; i < (cbTranslate / sizeof(struct LANGANDCODEPAGE)); i++)
		{
			wchar_t SubBlock[50] = { 0 };
			wsprintf(SubBlock, L"\\StringFileInfo\\%04x%04x\\CompanyName", lpTranslate[i].wLanguage,
				lpTranslate[i].wCodePage);
			UINT uLen;

			// Retrieve file description for language and code page "i". 
			if (VerQueryValueW(pVersionInfo,
				SubBlock,
				(LPVOID*)&pCompanyName,
				&uLen)) {

				return pCompanyName;
			}


		}

		//û�ɹ� û���� �п���û�й�˾����
		return nullptr;
	}

	auto get_file_companyname(const char* full_path) -> char*
	{

		DWORD dwDummy;
		char* pCompanyName;
		DWORD dwSize = GetFileVersionInfoSizeA(full_path, &dwDummy);
		UINT cbTranslate;

		if (dwSize == 0) {
			return nullptr;
		}



		BYTE* pVersionInfo = new BYTE[dwSize];
		if (!GetFileVersionInfoA(full_path, 0, dwSize, pVersionInfo)) {
			delete[] pVersionInfo;
			return nullptr;
		}


		struct LANGANDCODEPAGE {
			WORD wLanguage;
			WORD wCodePage;
		} *lpTranslate;

		// Read the list of languages and code pages.
		VerQueryValueA(pVersionInfo,
			("\\VarFileInfo\\Translation"),
			(LPVOID*)&lpTranslate,
			&cbTranslate);

		//��ȡҳ�� ֻ���������ܶ���
		for (int i = 0; i < (cbTranslate / sizeof(struct LANGANDCODEPAGE)); i++)
		{
			char SubBlock[50] = { 0 };
			sprintf(SubBlock, "\\StringFileInfo\\%04x%04x\\CompanyName", lpTranslate[i].wLanguage,
				lpTranslate[i].wCodePage);
			UINT uLen;

			// Retrieve file description for language and code page "i". 
			if (VerQueryValueA(pVersionInfo,
				SubBlock,
				(LPVOID*)&pCompanyName,
				&uLen)) {

				return pCompanyName;
			}


		}

		//û�ɹ� û���� �п���û�й�˾����
		return nullptr;
	}

	auto query_threads_by_pid(HANDLE pid) -> pthreads_info_t {

		NTSTATUS status;
		ULONG length;
		PSYSTEM_PROCESS_INFORMATION processInfo;
		PVOID buffer;
		PSYSTEM_THREAD_INFORMATION threadInfo;

		// ��ѯϵͳ������Ϣ�Ĵ�С
		status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &length);
		if (status != STATUS_INFO_LENGTH_MISMATCH)
		{

			return nullptr;
		}

		// �����ڴ滺����
		buffer = malloc(length);
		auto ret = (pthreads_info_t)nullptr;
		// ��ȡϵͳ������Ϣ
		status = ZwQuerySystemInformation(SystemProcessInformation, buffer, length, NULL);
		if (!NT_SUCCESS(status))
		{

			return nullptr;
		}

		// ���������б�
		processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
		do
		{
			if ((HANDLE)processInfo->UniqueProcessId == pid)
			{
				//���䷵���ڴ�
				ret = new threads_info_t;
				ret->threadsCount = processInfo->NumberOfThreads;
				ret->info = new thread_info_t[processInfo->NumberOfThreads];
				memset(ret->info, 0, processInfo->NumberOfThreads * sizeof thread_info_t);
				// �����߳��б�
				threadInfo = (PSYSTEM_THREAD_INFORMATION)(processInfo + 1);
				for (ULONG i = 0; i < processInfo->NumberOfThreads; i++)
				{
					auto& info = ret->info[i];
					sprintf_s(info.priority,"%d",threadInfo->Priority);
					sprintf_s(info.tid, "%d", threadInfo->ClientId.UniqueThread);
					sprintf_s(info.startAddr,"0x%p",threadInfo->StartAddress);
					sprintf(info.switchCount, "%d", threadInfo->Reserved3);
					
					threadInfo++;
				}


				//������Ϣȥ������query
				drv_load::io_ctl(CTL_QUERY_THREAD, ret, sizeof threads_info_t,
					0,0);
				
			}

			// �ƶ�����һ��������Ϣ
			if (processInfo->NextEntryOffset == 0)
			{
				break;
			}
			processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);

		} while (TRUE);


		return ret;

	}


	auto trans_time(LARGE_INTEGER time) -> QDateTime {
		SYSTEMTIME localTime;
		FILETIME fileTime{time.LowPart,time.HighPart}, localFileTime;


		FileTimeToLocalFileTime(&fileTime, &localFileTime);
		FileTimeToSystemTime(&localFileTime, &localTime);
		
		return QDateTime(QDate(localTime.wYear, localTime.wMonth, localTime.wDay)
			,QTime(localTime.wHour,localTime.wMinute,localTime.wSecond));
		
	}

	auto query_process_info(__inout pp_info info) -> bool {
		//ѯ������
		return drv_load::io_ctl(CTL_QUERY_PROCESS,info,sizeof p_info,info,sizeof p_info);
	}

	auto get_parent_pid(DWORD pid)->DWORD {
		// ��ȡ���̿���
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			return 0;
		}

		// ö�ٽ���
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) {
			CloseHandle(hSnapshot);
			return 0;
		}

		do {
			// �ҵ�ָ������
			if (pe32.th32ProcessID == pid) {
				CloseHandle(hSnapshot);
				return pe32.th32ParentProcessID;
			}
		} while (Process32Next(hSnapshot, &pe32));

		// û���ҵ�ָ������
		CloseHandle(hSnapshot);
		return 0;

	}

	auto enmu_process(QList<p_info>& info_list) -> void
	{

		//SystemProcessInformation

		NTSTATUS status = 0;
		size_t size = 0;
		SYSTEM_PROCESS_INFORMATION* buf = nullptr;
		ULONG needSize = 0;


		AllocConsole();
		freopen("CONOUT$", "w", stdout);

		PSYSTEM_PROCESS_INFORMATION psp = NULL;
		DWORD dwNeedSize = 0;
		status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &dwNeedSize);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			BYTE* pBuffer = new BYTE[dwNeedSize+PAGE_SIZE];

			status = ZwQuerySystemInformation(SystemProcessInformation, (PVOID)pBuffer, dwNeedSize+PAGE_SIZE, &dwNeedSize);
			if (status == 0)
			{
				psp = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
				do {

					p_info info{ 0 };
					 
					info.pid = (DWORD)psp->UniqueProcessId;
					//ת���ɶ��ֽ�
					sprintf(info.name, "%S", psp->ImageName.Buffer);
					info.sid = psp->SessionId;
					info.stime=trans_time(psp->CreateTime);
					info.ppid = get_parent_pid(info.pid);

					//ѯ����Ϣֻ��������
					query_process_info(&info);


					//printf("fullPath->%ws\r\n", info.fpath);
					info_list.append(info);
				
					//��һ��
					psp = (PSYSTEM_PROCESS_INFORMATION)((UINT_PTR)psp + psp->NextEntryOffset);
				} while (psp->NextEntryOffset != 0);
			}
			delete[] pBuffer;


			pBuffer = NULL;


		}

	}
	
	auto inject(HANDLE pid, const wchar_t* dll_path)->bool {

		inject_t buf = { .pid = pid,.dllPath={0} };
		wcscpy_s(buf.dllPath, dll_path);

		//ע��
		return drv_load::io_ctl(CTL_INJECT, &buf, sizeof inject_t, 0, 0);

	}

}