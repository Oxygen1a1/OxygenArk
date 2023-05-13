#include "_utils.hpp"

namespace _Utils {


	// 模式匹配
	auto pattern_check(const char* data, const char* pattern, const char* mask)->bool
	{
		size_t len = strlen(mask);

		for (size_t i = 0; i < len; i++)
		{
			if (data[i] == pattern[i] || mask[i] == '?')
				continue;
			else
				return false;
		}

		return true;
	}

	// 模式查找 不限于模块 size是判断的大小 pattern mask参考上面的
	auto find_pattern(unsigned long long addr, unsigned long size, const char* pattern, const char* mask) -> unsigned long long
	{
		
		size -= (unsigned long)strlen(mask);

		for (unsigned long i = 0; i < size; i++)
		{
			if (pattern_check((const char*)addr + i, pattern, mask))
				return addr + i;
		}

		return 0;
	}

	// 模式查找映像模式 给定模块基质 以及pattern+mask
	//默认text节
	//pattern k_utils::find_pattern_image(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".text");
	auto find_pattern_image(unsigned long long base, const char* pattern, const char* mask, const char* name)-> unsigned long long
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

		PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
		for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER p = &section[i];

			if (strstr((const char*)p->Name, name))
			{
				unsigned long long result = find_pattern(base + p->VirtualAddress, p->Misc.VirtualSize, pattern, mask);
				if (result) return result;
			}
		}

		return 0;
	}

	//给定模块地址 获取模块指定section的基质和大小
	auto get_section_address(unsigned long long addr, const char* section_name, __out unsigned long* size)-> unsigned long long
	{
		auto ret = 0ull;
		do {
			__try {

				PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
				if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

				PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(addr + dos->e_lfanew);
				if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

				PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
				for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++)
				{
					PIMAGE_SECTION_HEADER p = &section[i];

					if (strstr((const char*)p->Name, section_name))
					{
						if (size) *size = p->SizeOfRawData;
						ret= (unsigned long long)p + p->VirtualAddress;
						break;
					}
				}
			}
			__except (1) {
				ONLY_DEBUG_BREAK;
				break;
			}

		} while (false);

		return ret;
	}


	auto process_get_process_full_name(PEPROCESS Process, OUT wchar_t* out_name)->NTSTATUS
	{
		NTSTATUS status = STATUS_SUCCESS;


		PUNICODE_STRING FullName = NULL;
		NTSTATUS st = SeLocateProcessImageName(Process, &FullName);
		if (!NT_SUCCESS(st))
		{
			status = STATUS_UNSUCCESSFUL;
		}
		if (FullName->Buffer)
		{
			memcpy(out_name, FullName->Buffer, FullName->Length);
			status = STATUS_SUCCESS;
		}


		return status;
	}

	auto process_is_target_process(PEPROCESS target_process, const wchar_t* process_name)->bool {

		wchar_t* szName = (wchar_t*)ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, 111);

		if (!szName) {

			DbgPrintEx(77, 0, "[+]failed to alloc name\r\n");

			return false;
		}

		RtlSecureZeroMemory(szName, PAGE_SIZE);

		process_get_process_full_name(target_process, szName);

		if (wcsstr(szName, process_name)) {

			return true;

		}

		return false;

	}

	//暴力枚举PID 根据传入的进程名字获取PID
	auto process_force_enum_by_name(const wchar_t* szProcessName)->ULONG {
		ULONG i = 0;
		for (; i < 0x400000; i += 4)
		{
			PEPROCESS TargetProcess = NULL;
			NTSTATUS st = PsLookupProcessByProcessId(UlongToHandle(i), &TargetProcess);
			if (!NT_SUCCESS(st))
			{
				continue;
			}

			if (process_is_target_process(TargetProcess, szProcessName))
			{
				ObDereferenceObject(TargetProcess);
				break;
			}

		}

		return i;


	}

	//获取wow64进程 dll的导出函数 base是wdll.dll的基质 name是导出名字
	//process一定是一个wow进程
	auto find_module_export_wow64(PEPROCESS process, ULONG base,const char* name) -> ULONG {
		auto peb32 = undoc::PsGetProcessWow64Process(process);
		if (peb32 == nullptr) return 0;

		ULONG ret = 0;
		KAPC_STATE apc{ 0 };

		KeStackAttachProcess(process, &apc);
		
		do {

			__try {

				if (*((unsigned short*)base) != 0x5A4D) break;
				
				auto dosHeaders = (PIMAGE_DOS_HEADER)base;

				auto ntHeaders = (PIMAGE_NT_HEADERS32)(dosHeaders->e_lfanew + (UINT_PTR)base);

				auto exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)base + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

				//nameTable存的是函数名的RVA
				auto nameTable = (PULONG)(exportDirectory->AddressOfNames + (PUCHAR)base);
				//索引到funcTable索引转换需要这个
				auto ordinalTable = (PSHORT)(exportDirectory->AddressOfNameOrdinals + (PUCHAR)base);
				auto funcTable = (PULONG)(exportDirectory->AddressOfFunctions + (PUCHAR)base);

				for (auto i = 0ul; i < exportDirectory->NumberOfNames; i++) {

					if (strcmp((char*)base + nameTable[i], name) == 0) {
						//find
						auto index = ordinalTable[i];
						ret = base + funcTable[index];
						break;
					}

				}


			}
			__except (1) {

				break;
			}


		} while (false);

		KeUnstackDetachProcess(&apc);
		return ret;
	}

	//获取wow64进程wdll的基质
	auto find_module_base_wow64(PEPROCESS process,const wchar_t* dll_name)->ULONG {
		auto peb32 = undoc::PsGetProcessWow64Process(process);
		if (peb32 == nullptr) return 0;

		ULONG ret = 0;
		KAPC_STATE apc{ 0 };

		KeStackAttachProcess(process, &apc);

		do {
			__try {
				auto ldr = (UINT32)peb32->Ldr;
				auto head = (PLIST_ENTRY32)(ldr + 0xc);
				for (auto entry = (PLIST_ENTRY32)head->Flink; entry != head; entry = (PLIST_ENTRY32)entry->Flink) {

					wchar_t* dllName = (wchar_t*)*((PULONG)(((UINT64)entry + 0x30)));
					if (wcscmp(dllName, dll_name) == 0) {

						ret = *(PULONG)((UINT64)entry + 0x18);
						break;
					}

				}

			}
			__except (1) {


				break;
			}

		} while (false);


		KeUnstackDetachProcess(&apc);

		return ret;
	}

	//获取正常x64进程的导出函数 base是dll基质
	auto find_module_export(PEPROCESS process, UINT_PTR base,const char* name) -> UINT_PTR {
		KAPC_STATE apc{ 0 };
		auto ret = 0ull;
		KeStackAttachProcess(process, &apc);
		do {
			__try {

				auto dosHeaders = (PIMAGE_DOS_HEADER)base;

				auto ntHeaders = (PIMAGE_NT_HEADERS)(dosHeaders->e_lfanew + (UINT_PTR)base);

				auto exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)base + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

				//nameTable存的是函数名的RVA
				auto nameTable = (PULONG)(exportDirectory->AddressOfNames + (PUCHAR)base);
				//索引到funcTable索引转换需要这个
				auto ordinalTable = (PSHORT)(exportDirectory->AddressOfNameOrdinals + (PUCHAR)base);
				auto funcTable = (PULONG)(exportDirectory->AddressOfFunctions + (PUCHAR)base);

				for (auto i = 0ul; i < exportDirectory->NumberOfNames; i++) {

					if (strcmp((char*)base + nameTable[i], name) == 0) {

						//find
						auto index = ordinalTable[i];
						ret = (UINT_PTR)base + funcTable[index];
						break;
					}

				}

			}
			__except (1) {

				break;
			}

		} while (false);

		KeUnstackDetachProcess(&apc);
		return ret;

	}

	//根据模块base 查找函数的导出地址 只能用于内核！
	auto find_module_export(void* base,const char* name) -> void* {
		
		//为了确保查得到,需要进行附加explorer.exe 才能有地址空间 比如win32kxx.sys
		//要求调用这个函数的人必须是GUI线程 否则无法查找

		
		//explorer不一定能获取到?
		if (!MmIsAddressValid(base) || name == nullptr) return nullptr;
		__try {

			if (*((unsigned short*)base) != 0x5A4D) {
				
				return 0;//不是有效的PE文件
			}

			auto dosHeaders = (PIMAGE_DOS_HEADER)base;

			auto ntHeaders = (PIMAGE_NT_HEADERS)(dosHeaders->e_lfanew + (UINT_PTR)base);

			auto exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)base + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

			//nameTable存的是函数名的RVA
			auto nameTable = (PULONG)(exportDirectory->AddressOfNames + (PUCHAR)base);
			//索引到funcTable索引转换需要这个
			auto ordinalTable = (PSHORT)(exportDirectory->AddressOfNameOrdinals + (PUCHAR)base);
			auto funcTable = (PULONG)(exportDirectory->AddressOfFunctions + (PUCHAR)base);

			for (auto i = 0ul; i < exportDirectory->NumberOfNames; i++) {

				if (strcmp((char*)base + nameTable[i], name) == 0) {

					//find
					auto index = ordinalTable[i];
					auto ret = (UINT_PTR)base + funcTable[index];
					return (void*)ret;

				}

			}

			return 0;

		}
		__except (1) {
			
			return nullptr;
		}
		

		

	}

	//获取正常进程的dll基质 只用于R3的
	auto find_module_base(PEPROCESS process, const wchar_t* name) -> UINT_PTR {
		KAPC_STATE apc{ 0 };
		auto ret = 0ull;
		KeStackAttachProcess(process, &apc);

		do {

			__try {
				auto peb = undoc::PsGetProcessPeb(PsGetCurrentProcess());
				auto ldr = peb->Ldr;
				UNICODE_STRING uDllName{ 0 };

				RtlInitUnicodeString(&uDllName, name);
				//遍历LDR
				for (auto entry = ldr->InLoadOrderModuleList.Flink;
					entry != &ldr->InLoadOrderModuleList;
					entry = entry->Flink) {
					auto item = CONTAINING_RECORD(entry, undoc::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

					if (RtlEqualUnicodeString(&item->BaseDllName, &uDllName, true)) {
						ret = (UINT_PTR)item->DllBase;
						break;
					}

				}

			}
			__except (1) {

				break;

			}


		} while (false);

	
		KeUnstackDetachProcess(&apc);
		return ret;

	}

	//查找指定内核模块 只能内核
	auto find_module_base(const char* module_name) -> void* {

		wchar_t tmpName[260] = { 0 };

		_chartow(tmpName, module_name);
		for (auto entry=undoc::PsLoadedModuleList->Flink;entry!=undoc::PsLoadedModuleList;entry=entry->Flink) {
			auto item = CONTAINING_RECORD(entry, undoc::KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			
			if (wcscmp(tmpName, item->BaseDllName.Buffer) == 0) {
				//FIND
				return item->DllBase;
			}

		}
		return nullptr;
	}

	
	auto _chartow(wchar_t* dest, const char* source)->void {

		//防止R3传来的地址有问题,不能转换,先复制
		auto strLen = strlen(source);
		UNICODE_STRING uStr{0};
		ANSI_STRING aStr{ 0 };
		auto str = (char*)ExAllocatePoolWithTag(PagedPool, strLen + 1, 'tmp');
		if (!str) return;
		
		//清空
		memset(str, 0, strLen + 1);

		strcpy(str, source);
		RtlInitAnsiString(&aStr, str);
		//转换
		if(!NT_SUCCESS(RtlAnsiStringToUnicodeString(&uStr, &aStr, true))) return;

		//拷贝
		wcscpy(dest, uStr.Buffer);
		//释放内存
		RtlFreeUnicodeString(&uStr);

	}
	auto _wtochar(char* dest,const wchar_t* source)->void{

		if (dest == nullptr || source == nullptr) return;
		//防止R3传来的地址有问题,不能转换,先复制
		auto strLen = wcslen(source);
		UNICODE_STRING uStr{ 0 };
		ANSI_STRING aStr{ 0 };
		auto str = (wchar_t*)ExAllocatePoolWithTag(PagedPool, (strLen + 1)*2, 'tmp');
		if (!str) return;

		//清空
		memset(str,0, (strLen + 1) * 2);

		wcscpy(str, source);
		RtlInitUnicodeString(&uStr, str);
		//转换
		if (!NT_SUCCESS(RtlUnicodeStringToAnsiString(&aStr, &uStr, true))) return;

		//拷贝
		strcpy(dest, aStr.Buffer);
		RtlFreeAnsiString(&aStr);


	}

	//base是基数 即进制
	auto _atoi(char* asci,int base) -> LONG64 {
		ANSI_STRING tidString{ 0 };
		UNICODE_STRING tidUString{ 0 };
		//driver char*->intger
		RtlInitAnsiString(&tidString, asci);
		if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&tidUString,
			&tidString,
			true))) {
			LONG64 tid = 0;
			PWCHAR endPointer = nullptr;
			RtlUnicodeStringToInt64(&tidUString, base, &tid, &endPointer);

			//释放内存
			RtlFreeUnicodeString(&tidUString);
			return tid;
		}

		return 0;
	}

	//分配用户内存 前提是附加或者本身分配
	//失败返回nullptr
	auto _ualloc(size_t size,ULONG protect) -> void* {

		//必须对齐
		auto _size = (size_t)PAGE_ALIGN(size)+PAGE_SIZE;
		void* ret = nullptr;

		auto status=ZwAllocateVirtualMemory(ZwCurrentProcess(),&ret,0,&_size,MEM_COMMIT, protect);

		if (!NT_SUCCESS(status)) return nullptr;

		return ret;
	}


	//获取KiSystemServiceUser
	auto get_syscall_entry() -> void*
	{
		auto ntoskrnl = (UINT_PTR)find_module_base("ntoskrnl.exe");
		if (!ntoskrnl) return nullptr;

		/*
		2018年的内核页表隔离补丁 https://bbs.pediy.com/thread-223805.htm
		没有补丁的话就是KiSystemCall64
		*/
#define IA32_LSTAR_MSR 0xC0000082
		void* syscall_entry = (void*)__readmsr(IA32_LSTAR_MSR);

		// 没有补丁过,直接返回KiSystemCall64就行
		unsigned long section_size = 0;
		unsigned long long KVASCODE = get_section_address(ntoskrnl, "KVASCODE", &section_size);
		if (!KVASCODE) return syscall_entry;

		// KiSystemCall64还是在区域内,也是直接返回
		if (!(syscall_entry >= (void*)KVASCODE && syscall_entry < (void*)(KVASCODE + section_size))) return syscall_entry;

		// 来到这一步那就是KiSystemCall64Shadow,代表打补丁了
		hde64s hde_info{ 0 };
		for (char* ki_system_service_user = (char*)syscall_entry; ; ki_system_service_user += hde_info.len)
		{
			// 反汇编
			if (!hde64_disasm(ki_system_service_user, &hde_info)) break;

			// 我们要查找jmp
#define OPCODE_JMP_NEAR 0xE9
			if (hde_info.opcode != OPCODE_JMP_NEAR) continue;

			// 忽略在KVASCODE节区内的jmp指令
			void* possible_syscall_entry = (void*)((long long)ki_system_service_user + (int)hde_info.len + (int)hde_info.imm.imm32);
			if (possible_syscall_entry >= (void*)KVASCODE && possible_syscall_entry < (void*)((unsigned long long)KVASCODE + section_size)) continue;

			// 发现KiSystemServiceUser
			syscall_entry = possible_syscall_entry;
			break;
		}

		return syscall_entry;
	}

	auto get_ssdt() -> UINT_PTR {
		auto KiSystemServiceUser = get_syscall_entry();
		auto ssdt = 0ull;
		//4C 8D 15 85 6F 9F 00          lea     r10, KeServiceDescriptorTable
		//4C 8D 1D FE 20 8F 00          lea     r11, KeServiceDescriptorTableShadow
		do {
			__try {

				auto ret=find_pattern((unsigned long long)KiSystemServiceUser, 0x500,
					"\x4c\x8d\x15\x00\x00\x00\x00\x4c\x8d\x1d\x00\x00\x00\x00",
					"xxx????xxx????");
				//获取偏移
				int offset = *(int*)(ret + 3);
				ssdt = ret + 7 + offset;
			}
			__except (1) {

				break;
			}

		} while (false);

		return ssdt;
	}

	auto get_sssdt() -> UINT_PTR {
		
		auto KiSystemServiceUser = get_syscall_entry();
		auto ssdt = 0ull;
		//4C 8D 15 85 6F 9F 00          lea     r10, KeServiceDescriptorTable
		//4C 8D 1D FE 20 8F 00          lea     r11, KeServiceDescriptorTableShadow
		do {
			__try {

				auto ret = find_pattern((unsigned long long)KiSystemServiceUser, 0x500,
					"\x4c\x8d\x15\x00\x00\x00\x00\x4c\x8d\x1d\x00\x00\x00\x00",
					"xxx????xxx????");
				//获取偏移
				int offset = *(int*)(ret + 10);
				ssdt = ret + 14 + offset;
			}
			__except (1) {

				break;
			}

		} while (false);

		return ssdt;
	}

	//获取NT函数的ssdt index
	auto get_ntfunc_index(const char* name) -> unsigned int {

		auto base=find_module_base(IoGetCurrentProcess(), L"ntdll.dll");
		auto ntFunc = find_module_export(IoGetCurrentProcess(),base, name);

		auto index = 0ul;

		do {
			__try {
				for (int i = 0; i < 0x30; i++) {
					if (((PUCHAR)ntFunc)[i] == (UCHAR)(0xb8)) {
						index = *((unsigned int*)(ntFunc +i+ 1));
						break;
					}
				}
			}
			__except (1) {
				break;
			}

		} while (false);
		//找到B8(mov eax,xxx)
		return index;

	}

	//根据SSDT 和(ntdll)Nt函数名 获取内核的Nt函数
	//不要在DriverEntry里面获取不然获取不到
	auto get_nt_func(const char* name) -> UINT_PTR {
		auto index = get_ntfunc_index(name);
		if (index == 0) return 0;
		auto func = 0ull;
		//获取SSDT
		auto ssdt = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)get_ssdt();

		do {
			__try {

				if (index > ssdt[0].NumberOfServices) break;

				//应该是有符号的
				auto offset = ssdt[0].ServiceTableBase[index];
				//把他扩展
				long long soffset = (long long)offset;
				//然后sar(带符号扩展地右移4位)
				soffset=soffset >> 4;
				//然后转换成无符号
				unsigned long long uoffset = (unsigned long long)(soffset);
				func = uoffset + (UINT_PTR)ssdt[0].ServiceTableBase;

				break;
			}
			__except (1) { break; }

		} while (false);

		return func;
	}

	//修改PreviousMode
	auto change_pre_mode(MODE m) -> MODE {

		UNICODE_STRING usFunc{ 0 };
		RtlInitUnicodeString(&usFunc, L"ExGetPreviousMode");
		MODE ret = KernelMode;

		auto offset = 0ul;
		auto start = (PUCHAR)MmGetSystemRoutineAddress(&usFunc);
		__try {
			//65 48 8B 04 25 88 01 00 00		mov     rax, gs:188h
			//	0F B6 80 32 02 00 00          movzx   eax, byte ptr[rax + 232h]
			//	C3                            retn
			for (int i = 0; i < 0x30; i++) {

				if (start[i] == (UCHAR)(0xC3)) {

					offset = *(PULONG)(&(start[i - 4]));
					ret = (MODE)((UCHAR*)PsGetCurrentThread())[offset];
					((CHAR*)PsGetCurrentThread())[offset] = (CHAR)m;
					break;
				}
			}

		}
		__except (1) {

			
		}

		return ret;
	}

	//恢复线程的PreviousMode
	auto resume_pre_mode(MODE o) -> void {

		UNICODE_STRING usFunc{ 0 };
		RtlInitUnicodeString(&usFunc, L"ExGetPreviousMode");
		auto offset = 0ul;
		auto start = (PUCHAR)MmGetSystemRoutineAddress(&usFunc);
		__try {
			//65 48 8B 04 25 88 01 00 00		mov     rax, gs:188h
			//	0F B6 80 32 02 00 00          movzx   eax, byte ptr[rax + 232h]
			//	C3                            retn
			for (int i = 0; i < 0x30; i++) {

				if (start[i] == (UCHAR)(0xC3)) {

					offset = *(PULONG)(&(start[i - 4]));
					((CHAR*)PsGetCurrentThread())[offset] = (CHAR)o;
					break;
				}
			}

		}
		__except (1) {


		}


	}
}