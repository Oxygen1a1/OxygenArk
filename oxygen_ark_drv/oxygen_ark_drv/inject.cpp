#include "inject.hpp"

namespace inject {


	auto inject_x86(PEPROCESS process,const wchar_t* dll_path) -> bool {
		wchar_t dllPath[MAX_PATH] = { 0 };
		wcscpy(dllPath, dll_path);
		KAPC_STATE apc{ 0 };
		//先分配内存
		bool ret = false;
		KeStackAttachProcess(process, &apc);

		do {
			__try {
				auto procDll = _Utils::_ualloc(PAGE_SIZE, PAGE_READWRITE);
				if (procDll == nullptr) break;

				//复制一下
				memset(procDll, 0, PAGE_SIZE);
				memcpy(procDll, dllPath, MAX_PATH);

				//然后+0x500位置就是UNICODE_STRING*
				auto usprocDll = (PUNICODE_STRING_x86)((ULONG)procDll + 0x500);
				
				//初始化x86的UNICODE_STRING
				usprocDll->Length = (USHORT)wcslen((wchar_t*)procDll)*2;
				usprocDll->MaximumLength = usprocDll->Length+2;
				usprocDll->Buffer = (ULONG)(procDll);

				//获取x86的LdrLoadDll
				auto LdrLoadDll=_Utils::find_module_export_wow64(process, 
					_Utils::find_module_base_wow64(process,L"ntdll.dll"), 
					"LdrLoadDll");
				//分配shellcode
				auto shellcode=_Utils::_ualloc(PAGE_SIZE, PAGE_EXECUTE_READWRITE);

				//写入shellcode
				memcpy(shellcode, x86_shellcode, sizeof x86_shellcode);

				//按照结构解析
				((px86_shellcode_t)(shellcode))->dllPath = (ULONG)usprocDll;
				((px86_shellcode_t)(shellcode))->LdrLoadDll = LdrLoadDll;

				//获取NtCreateThreadEx函数
				fnNtCreateThreadEx NtCreateThreadEx = 
					(fnNtCreateThreadEx)_Utils::get_nt_func("NtCreateThreadEx");
				//需要修改PreviousMode

				HANDLE hThread = 0;
				auto oMode=_Utils::change_pre_mode(KernelMode);
				auto status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), 
					(PVOID)shellcode, NULL, 0, 0, 0, 0, 0);
				//恢复PreviousMode
				_Utils::resume_pre_mode(oMode);
				if (!NT_SUCCESS(status)) break;

				//成功 去执行shellcode了
				ret = true;
				break;
			
			}
			__except (1) { break; }
			

			//填入
		} while (false);


		KeUnstackDetachProcess(&apc);
		return ret;
	}

	auto inject_x64(PEPROCESS process, const wchar_t* dll_path) -> bool {
		
		wchar_t dllPath[MAX_PATH] = { 0 };
		wcscpy(dllPath, dll_path);
		KAPC_STATE apc{ 0 };
		//先分配内存
		bool ret = false;
		KeStackAttachProcess(process, &apc);

		do {
			__try {

				//先分配内存
				auto procDll = _Utils::_ualloc(PAGE_SIZE,PAGE_READWRITE);
				if (procDll == nullptr) break;

				//把dll名称复制过去
				memcpy(procDll, dll_path, MAX_PATH);
				auto usprocDll = (UINT64)procDll + 0x500;
				RtlInitUnicodeString((PUNICODE_STRING)usprocDll, (PCWSTR)procDll);

				//分配shellcode
				auto shellcode = _Utils::_ualloc(PAGE_SIZE, PAGE_EXECUTE_READWRITE);
				if (shellcode == nullptr) break;
				memcpy(shellcode, x64_shellcode, sizeof x64_shellcode);

				//查找LdrLoadDll
				auto LdrLoadDll = _Utils::find_module_export(process,
					_Utils::find_module_base(process, L"ntdll.dll"),
					"LdrLoadDll");
				((px64_shellcode_t)shellcode)->LdrLoadDll = LdrLoadDll;
				((px64_shellcode_t)shellcode)->dllPath = (PUNICODE_STRING)usprocDll;

				//获取NtCreateThreadEx函数
				fnNtCreateThreadEx NtCreateThreadEx =
					(fnNtCreateThreadEx)_Utils::get_nt_func("NtCreateThreadEx");

				HANDLE hThread = 0;
				auto oMode = _Utils::change_pre_mode(KernelMode);
				auto status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(),
					(PVOID)shellcode, NULL, 0, 0, 0, 0, 0);
				//恢复PreviousMode
				_Utils::resume_pre_mode(oMode);
				if (!NT_SUCCESS(status)) break;

				//成功 去执行shellcode了
				ret = true;
				break;

			}
			__except (1) {
				break;
			}


		} while (false);


		KeUnstackDetachProcess(&apc);


		return ret;
	}
}