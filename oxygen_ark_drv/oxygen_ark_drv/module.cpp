#include "module.hpp"

using namespace undoc;
namespace Module {


	auto query_process_module_count(PEPROCESS process) -> UINT64 {
		KAPC_STATE apc{ 0 };

		KeStackAttachProcess(process, &apc);
		//����LDR
		auto peb = PsGetProcessPeb(process);

		auto ldr = peb->Ldr;
		auto moduleCount = 0;
		for (auto entry = ldr->InLoadOrderModuleList.Flink;
			entry != &ldr->InLoadOrderModuleList;
			entry = entry->Flink) {
			//��ȡģ������
			moduleCount++;
		}

		KeUnstackDetachProcess(&apc);
		return moduleCount;
	}

	auto enum_process_modules(PEPROCESS process, pmodules_info_t moduleInfos) -> bool {
		//���������ĵ�  һ��Ҫ�Լ������ڴ� ���ƹ�ȥ ��ȻKeStackAttch����
		//����LDR

		if (!MmIsAddressValid(moduleInfos->modules)) return false;
		KAPC_STATE apc{ 0 };
		//�����ڴ�
		auto tmp = (pmodule_info_t)ExAllocatePoolWithTag(PagedPool, moduleInfos->moduleCount * sizeof module_info_t,
			'modu');
		//�ҿ�
		KeStackAttachProcess(process, &apc);
		//Ҫ��ǰ�ҿ�,��Ȼ����
		auto peb= PsGetProcessPeb(process);

		auto ldr = peb->Ldr;

		
		int index = 0;
		for (auto entry = ldr->InLoadOrderModuleList.Flink;
			entry != &ldr->InLoadOrderModuleList;
			entry = entry->Flink) {
			auto item = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			
			char fullName[MAX_PATH]{ 0 };
			

			_Utils::_wtochar(fullName, item->FullDllName.Buffer);

			strcpy_s(tmp[index].path, fullName);

			RtlStringCchPrintfA(tmp[index].moduleStart,MAX_PATH,"0x%p",item->DllBase);
			RtlStringCchPrintfA(tmp[index].moduleEnd, MAX_PATH, "0x%llx", 
				((UINT64)item->DllBase+item->SizeOfImage));
			index++;
		}

		KeUnstackDetachProcess(&apc);

		//��ʼ����
		for (int i = 0; i < moduleInfos->moduleCount; i++) {	
			strcpy_s(moduleInfos->modules[i].moduleStart, tmp[i].moduleStart);
			strcpy_s(moduleInfos->modules[i].moduleEnd, tmp[i].moduleEnd);
			strcpy_s(moduleInfos->modules[i].path, tmp[i].path);
		}

		ExFreePool(tmp);
		return true;
	}

	auto get_file_module_name(PEPROCESS process,UINT_PTR addr,__out char* moduleName) -> bool {
		
		//����ҿ�
		KAPC_STATE apc{ 0 };
		KeStackAttachProcess(process, &apc);
		auto peb = PsGetProcessPeb(process);
		auto ldr = peb->Ldr;

		auto nameTmp = (char*)ExAllocatePoolWithTag(PagedPool, MAX_PATH, 'MODU');
		

		

		for (auto entry = ldr->InLoadOrderModuleList.Flink;
			entry != &ldr->InLoadOrderModuleList;
			entry = entry->Flink) {
			auto item = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (addr >= (UINT_PTR)item->DllBase && addr <= (UINT_PTR)item->DllBase+item->SizeOfImage) {

				_Utils::_wtochar(nameTmp, item->BaseDllName.Buffer);

				break;
			}

		}

		KeUnstackDetachProcess(&apc);

		strcpy_s(moduleName, MAX_PATH, nameTmp);
		ExFreePool(nameTmp);

		return true;
	}

	auto get_file_module_name(HANDLE pid, UINT_PTR addr, __out char* moduleName) -> bool {

		//����ҿ�
		KAPC_STATE apc{ 0 };
		PEPROCESS process{ 0 };
		if (!NT_SUCCESS(PsLookupProcessByProcessId(pid,&process))) {
			
			//���
			moduleName[0] = 0;
			return false;
		}

		ObDereferenceObject(process);

		KeStackAttachProcess(process, &apc);
		auto peb = PsGetProcessPeb(process);
		auto ldr = peb->Ldr;

		auto nameTmp = (char*)ExAllocatePoolWithTag(PagedPool, MAX_PATH, 'MODU');
		memset(nameTmp, 0,MAX_PATH);



		for (auto entry = ldr->InLoadOrderModuleList.Flink;
			entry != &ldr->InLoadOrderModuleList;
			entry = entry->Flink) {
			auto item = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (addr >= (UINT_PTR)item->DllBase && addr <= (UINT_PTR)item->DllBase + item->SizeOfImage) {

				_Utils::_wtochar(nameTmp, item->BaseDllName.Buffer);

				break;
			}

		}

		KeUnstackDetachProcess(&apc);

		strcpy_s(moduleName, MAX_PATH, nameTmp);
		ExFreePool(nameTmp);

		return true;
	}

}