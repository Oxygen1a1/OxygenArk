#include "inject.hpp"

namespace inject {


	auto inject_x86(PEPROCESS process,const wchar_t* dll_path) -> bool {
		wchar_t dllPath[MAX_PATH] = { 0 };
		wcscpy(dllPath, dll_path);
		KAPC_STATE apc{ 0 };
		//�ȷ����ڴ�
		bool ret = false;
		KeStackAttachProcess(process, &apc);

		do {
			__try {
				auto procDll = _Utils::_ualloc(PAGE_SIZE, PAGE_READWRITE);
				if (procDll == nullptr) break;

				//����һ��
				memset(procDll, 0, PAGE_SIZE);
				memcpy(procDll, dllPath, MAX_PATH);

				//Ȼ��+0x500λ�þ���UNICODE_STRING*
				auto usprocDll = (PUNICODE_STRING_x86)((ULONG)procDll + 0x500);
				
				//��ʼ��x86��UNICODE_STRING
				usprocDll->Length = (USHORT)wcslen((wchar_t*)procDll)*2;
				usprocDll->MaximumLength = usprocDll->Length+2;
				usprocDll->Buffer = (ULONG)(procDll);

				//��ȡx86��LdrLoadDll
				auto LdrLoadDll=_Utils::find_module_export_wow64(process, 
					_Utils::find_module_base_wow64(process,L"ntdll.dll"), 
					"LdrLoadDll");
				//����shellcode
				auto shellcode=_Utils::_ualloc(PAGE_SIZE, PAGE_EXECUTE_READWRITE);

				//д��shellcode
				memcpy(shellcode, x86_shellcode, sizeof x86_shellcode);

				//���սṹ����
				((px86_shellcode_t)(shellcode))->dllPath = (ULONG)usprocDll;
				((px86_shellcode_t)(shellcode))->LdrLoadDll = LdrLoadDll;

				//��ȡNtCreateThreadEx����
				fnNtCreateThreadEx NtCreateThreadEx = 
					(fnNtCreateThreadEx)_Utils::get_nt_func("NtCreateThreadEx");
				//��Ҫ�޸�PreviousMode

				HANDLE hThread = 0;
				auto oMode=_Utils::change_pre_mode(KernelMode);
				auto status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), 
					(PVOID)shellcode, NULL, 0, 0, 0, 0, 0);
				//�ָ�PreviousMode
				_Utils::resume_pre_mode(oMode);
				if (!NT_SUCCESS(status)) break;

				//�ɹ� ȥִ��shellcode��
				ret = true;
				break;
			
			}
			__except (1) { break; }
			

			//����
		} while (false);


		KeUnstackDetachProcess(&apc);
		return ret;
	}

	auto inject_x64(PEPROCESS process, const wchar_t* dll_path) -> bool {
		
		wchar_t dllPath[MAX_PATH] = { 0 };
		wcscpy(dllPath, dll_path);
		KAPC_STATE apc{ 0 };
		//�ȷ����ڴ�
		bool ret = false;
		KeStackAttachProcess(process, &apc);

		do {
			__try {

				//�ȷ����ڴ�
				auto procDll = _Utils::_ualloc(PAGE_SIZE,PAGE_READWRITE);
				if (procDll == nullptr) break;

				//��dll���Ƹ��ƹ�ȥ
				memcpy(procDll, dll_path, MAX_PATH);
				auto usprocDll = (UINT64)procDll + 0x500;
				RtlInitUnicodeString((PUNICODE_STRING)usprocDll, (PCWSTR)procDll);

				//����shellcode
				auto shellcode = _Utils::_ualloc(PAGE_SIZE, PAGE_EXECUTE_READWRITE);
				if (shellcode == nullptr) break;
				memcpy(shellcode, x64_shellcode, sizeof x64_shellcode);

				//����LdrLoadDll
				auto LdrLoadDll = _Utils::find_module_export(process,
					_Utils::find_module_base(process, L"ntdll.dll"),
					"LdrLoadDll");
				((px64_shellcode_t)shellcode)->LdrLoadDll = LdrLoadDll;
				((px64_shellcode_t)shellcode)->dllPath = (PUNICODE_STRING)usprocDll;

				//��ȡNtCreateThreadEx����
				fnNtCreateThreadEx NtCreateThreadEx =
					(fnNtCreateThreadEx)_Utils::get_nt_func("NtCreateThreadEx");

				HANDLE hThread = 0;
				auto oMode = _Utils::change_pre_mode(KernelMode);
				auto status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(),
					(PVOID)shellcode, NULL, 0, 0, 0, 0, 0);
				//�ָ�PreviousMode
				_Utils::resume_pre_mode(oMode);
				if (!NT_SUCCESS(status)) break;

				//�ɹ� ȥִ��shellcode��
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