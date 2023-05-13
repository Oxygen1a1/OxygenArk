#include "process.hpp"

using namespace undoc;

namespace kprocess {


	//�����infos.tid��startaddress����
	auto query_threads_info(pthreads_info_t infos)->NTSTATUS {
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		if (MmIsAddressValid(infos->info)) {
			for (int i = 0; i < infos->threadsCount; i++) {
				auto tid = _Utils::_atoi(infos->info[i].tid);
				PETHREAD thread{ 0 };
				if (NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)tid, &thread))) {
					RtlStringCchPrintfA(infos->info[i].ethread, MAX_PATH, "0x%p", thread);
					RtlStringCchPrintfA(infos->info[i].teb, MAX_PATH, "0x%p", PsGetThreadTeb(thread));
					
					ULONG64 addr = (ULONG64)_Utils::_atoi(infos->info[i].startAddr,16);
					//��ȡģ��
					Module::get_file_module_name(PsGetThreadProcess(thread),addr,infos->info[i].moduleName);
				}
				
	
			}

		}
		return status;
	}

	auto terminate_process(HANDLE pid) -> NTSTATUS {
		HANDLE hProcess = 0;
		NTSTATUS status;
		OBJECT_ATTRIBUTES oa{ 0 };
		PEPROCESS process{ 0 };

		status = PsLookupProcessByProcessId(pid,&process);
		if (!NT_SUCCESS(status)) return status;
		ObDereferenceObject(process);

		::CLIENT_ID id{ id.UniqueProcess = PsGetProcessId(process),0 };
		ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &id);

		status =ZwTerminateProcess(hProcess, 0);
		ZwClose(hProcess);
		return status;

	}

	auto hide_process(HANDLE pid) -> bool {

		return HIDE_PROCESS::unlink_process(pid);

	}

	//ѯ�ʽ��̵������߳�ID
	auto query_threads_tid(HANDLE pid) -> HANDLE* {
		NTSTATUS status;
		ULONG length;
		undoc::PSYSTEM_PROCESS_INFORMATION processInfo=nullptr;
		undoc::PSYSTEM_THREAD_INFORMATION threadInfo;

		status = undoc::ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &length);
		if (status != STATUS_INFO_LENGTH_MISMATCH)
		{

			return nullptr;
		}

		
		processInfo = (undoc::PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(
			PagedPool,length+PAGE_SIZE,'tmp');
		auto buf = processInfo;
		// ��ȡϵͳ������Ϣ
		status = ZwQuerySystemInformation(SystemProcessInformation, 
			processInfo, length, NULL);
		if (!NT_SUCCESS(status))
		{

			return nullptr;
		}

		HANDLE* ret = nullptr;
		//ѭ��
		do
		{
			if ((HANDLE)processInfo->UniqueProcessId == pid)
			{
				//���䷵���ڴ�
				// �����߳��б�
				threadInfo = (PSYSTEM_THREAD_INFORMATION)(processInfo + 1);
				ret = (HANDLE*)ExAllocatePoolWithTag(PagedPool,
					processInfo->NumberOfThreads * sizeof HANDLE+1, 'ret');

				ret[processInfo->NumberOfThreads] = 0;//��β����
				for (ULONG i = 0; i < processInfo->NumberOfThreads; i++)
				{
				
					ret[i] = threadInfo[i].ClientId.UniqueThread;
					

				}

				break;
			}

			// �ƶ�����һ��������Ϣ
			if (processInfo->NextEntryOffset == 0)
			{
				break;
			}
			processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);


		} while (TRUE);

		ExFreePool(buf);

		return ret;
	}


	auto user_cannot_access(PEPROCESS process) -> bool {
		
		UNICODE_STRING funcName{ 0 };
		RtlInitUnicodeString(&funcName, L"PsIsProtectedProcess");
		bool nonAccess = false;

		bool (*func)(PEPROCESS) = (bool(*)(PEPROCESS))MmGetSystemRoutineAddress(&funcName);
		//����PsIsProtectedProcess�ж�
		if (func !=nullptr) {

			nonAccess = func(process);

		}

		auto header = (POBJECT_HEADER)((UINT64)process - 0x30);
		//��ObjectHeader->KernelOnlyAccess
		nonAccess |= header->KernelOnlyAccess;
		return nonAccess;

	}


	auto query_process_info(pp_info info,PEPROCESS process)->bool {
		KAPC_STATE apc{ 0 };
		
		KeStackAttachProcess(process, &apc);

		__try {

			auto peb=PsGetProcessPeb(process);
		

			if (MmIsAddressValid(peb)) {
				
				//��ʼ����
				memcpy(info->cmdline, peb->ProcessParameters->CommandLine.Buffer, MAX_PATH);
				memcpy(info->fpath, peb->ProcessParameters->ImagePathName.Buffer, MAX_PATH);
				auto uAccess = user_cannot_access(process);
				info->uaccess = !uAccess;
			}
		}
		__except (1) {

			KeUnstackDetachProcess(&apc);
			return false;
		}

		KeUnstackDetachProcess(&apc);
		return true;
	}


	auto query_process_handle_count(HANDLE pid) -> unsigned int {

		auto count = 0ul;
		auto needSize = 0ul;

		auto tmp = ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, 'tmp');
		if (tmp == nullptr) return false;
		auto status = ZwQuerySystemInformation(SystemHandleInformation, tmp, PAGE_SIZE, &needSize);
		ExFreePool(tmp);


		if (status != STATUS_INFO_LENGTH_MISMATCH) {
			return 0;
		}

		//������
		auto buf = (PSYSTEM_HANDLE_INFORMATION)ExAllocatePoolWithTag(PagedPool, needSize+PAGE_SIZE, 'tmp');

		status = ZwQuerySystemInformation(SystemHandleInformation, buf, needSize + PAGE_SIZE, &needSize);
		if (!NT_SUCCESS(status)) {
			ExFreePool(buf);
			return 0;
		}

		//��ʼbianli 
		for (auto i = 0ul; i < buf->NumberOfHandles; i++) {

			auto item = buf->Handles[i];

			if (pid == (HANDLE)item.pid) {
				count++;

			}
		}

		ExFreePool(buf);
		return count;

	}
	
	//���ؽ��̵ľ����Ϣ �ǵð�������������
	auto query_process_handles(HANDLE pid, phandles_info_t infos) -> bool {

		//ѯ�ʸý��̾������
		auto count = query_process_handle_count(pid);
		if (count == 0) return false;

		if (count > infos->count) return false;//��������С
		__try {

			//��һ�´���Ļ������Ƿ�����
			infos->infos[count] = {0};
		}
		__except (1) {

			//������̫С
			return false;
		}

		//�ǵ�����
		infos->count = 0;
		//������е��ڴ� ��Ȼ������˵�����ж���
		auto tmp = ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, 'tmp');
		if (tmp == nullptr) return false;

		auto needSize = 0ul;
		auto status = ZwQuerySystemInformation(SystemHandleInformation, tmp, PAGE_SIZE, &needSize);
		ExFreePool(tmp);

		if (status != STATUS_INFO_LENGTH_MISMATCH) {
			return false;
		}
		//������
		auto buf = (PSYSTEM_HANDLE_INFORMATION)ExAllocatePoolWithTag(PagedPool, needSize + PAGE_SIZE, 'tmp');
		if (buf == nullptr) return false;

		status = ZwQuerySystemInformation(SystemHandleInformation, buf, needSize + PAGE_SIZE, &needSize);
		if (!NT_SUCCESS(status)) {
			ExFreePool(buf);
			return false;
		}

		

		//��ʼѯ�ʾ�����Ϣ

		//��ʼbianli 
		for (auto i = 0ul; i < buf->NumberOfHandles; i++) {
			PEPROCESS process{ 0 };
			KAPC_STATE apc{ 0 };
			auto item = buf->Handles[i];

			if ((HANDLE)item.pid == pid) {

				PsLookupProcessByProcessId((HANDLE)item.pid, &process);
				KeStackAttachProcess(process, &apc);

				OBJECT_BASIC_INFORMATION obi{ 0 };
				OBJECT_NAME_INFORMATION* oni{ 0 };
				OBJECT_TYPE_INFORMATION* oti{ 0 };
				OBJECT_HANDLE_FLAG_INFORMATION ohf{ 0 };

				status = ZwQueryObject((HANDLE)item.HandleValue, (OBJECT_INFORMATION_CLASS)0,
					&obi, sizeof obi, 0);


				oni = (OBJECT_NAME_INFORMATION*)ExAllocatePoolWithTag(PagedPool, sizeof OBJECT_NAME_INFORMATION, 'tmp');
				memset(oni, 0, sizeof OBJECT_NAME_INFORMATION);
				status = ZwQueryObject(((HANDLE)item.HandleValue), (OBJECT_INFORMATION_CLASS)undoc::ObjectNameInformation
					, oni, sizeof oni, &needSize
				);
				if (oni == nullptr) { KeUnstackDetachProcess(&apc); return false; }
				if (status == STATUS_INFO_LENGTH_MISMATCH) {
					ExFreePool(oni);
					oni = nullptr;
					oni = (OBJECT_NAME_INFORMATION*)ExAllocatePoolWithTag(PagedPool, needSize, 'tmp');
					if (oni == nullptr) { KeUnstackDetachProcess(&apc); return false; }
					status = ZwQueryObject(((HANDLE)item.HandleValue), (OBJECT_INFORMATION_CLASS)undoc::ObjectNameInformation
						, oni, needSize, &needSize
					);
				}


				oti = (OBJECT_TYPE_INFORMATION*)ExAllocatePoolWithTag(PagedPool, sizeof OBJECT_TYPE_INFORMATION, 'tmp');
				if (oti == nullptr) { KeUnstackDetachProcess(&apc); return false; }

				status = ZwQueryObject(((HANDLE)item.HandleValue), (OBJECT_INFORMATION_CLASS)undoc::ObjectTypeInformation
					, oti, sizeof OBJECT_TYPE_INFORMATION, &needSize
				);

				if (status == STATUS_INFO_LENGTH_MISMATCH) {
					ExFreePool(oti);
					oti = nullptr;
					oti = (OBJECT_TYPE_INFORMATION*)ExAllocatePoolWithTag(PagedPool, needSize, 'tmp');
					if (oti == nullptr) { KeUnstackDetachProcess(&apc); return false; }


					memset(oti, 0, needSize);
					status = ZwQueryObject(((HANDLE)item.HandleValue), (OBJECT_INFORMATION_CLASS)undoc::ObjectTypeInformation
						, oti, needSize, &needSize
					);

				}

				status = ZwQueryObject(((HANDLE)item.HandleValue), (OBJECT_INFORMATION_CLASS)undoc::ObjectHandleFlagInformation
					, &ohf, sizeof ohf, 0
				);

				
				KeUnstackDetachProcess(&apc);

				//��ʼ���� һ��Ҫȡ���ҿ� ��Ȼ����
				auto cur_index = infos->count;
				infos->infos[cur_index] = { .access = item.GrantedAccess,
				.handleType = 0,.handleName = 0,.handle = (HANDLE)item.HandleValue,
				.handleObject = (UINT_PTR)item.Object,.ptrRef = obi.PointerCount,
				.handleRef = obi.HandleCount,.closeProtect = ohf.ProtectFromClose
				};

				//��ʼ����TypeName��Name
				_Utils::_wtochar(infos->infos[cur_index].handleName, oni->Name.Buffer);
				_Utils::_wtochar(infos->infos[cur_index].handleType, oti->TypeName.Buffer);
				infos->count++;
				ExFreePool(oti);
				ExFreePool(oni);
			}

		}

		return true;
	}




	//�����߳�ע��
	//��Ҫ���
	//1.hide memory
	//2.��������
	//3.�޸�StartAddress��ntdll��
	//4.���PEͷ
	//�ͷ��ڴ�

	
}