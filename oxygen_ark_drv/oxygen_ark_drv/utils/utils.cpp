#include "utils.h"

Utils* Utils::m_Instance;

Utils* Utils::fn_get_instance()
{
	if (m_Instance == 0) {

		m_Instance = (Utils*)ExAllocatePoolWithTag(NonPagedPool, sizeof(Utils), 'util');
	
		//����Ĵ��ڴ� ���HookInfo����
		m_Instance->m_tramp_line = (uint8_t*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE*10, 'util');
		m_Instance->m_tramp_line_used = 0;
		m_Instance->m_count = 0;
		if (m_Instance == 0 || m_Instance->m_tramp_line==0) {
			
			DbgPrintEx(77, 0, "[+]failed to alloc instance\r\n");
			return 0;
		}

		RtlSecureZeroMemory(m_Instance->m_hook_info_table, MAX_HOOK_COUNT * sizeof(HOOK_INFO));

	}

	return m_Instance;
}

uint32_t Utils::fn_get_os_build_number()
{
	unsigned long number = 0;
	RTL_OSVERSIONINFOEXW info{ 0 };
	info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
	if (NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&info))) number = info.dwBuildNumber;
	return number;
}

//��ȡϵͳģ��Ļ���
uint64_t Utils::fn_get_moudle_address(const char* name, unsigned long* size)
{
	unsigned long long result = 0;

	unsigned long length = 0;
	ZwQuerySystemInformation(11, &length, 0, &length);
	if (!length) return result;

	const unsigned long tag = 'VMON';
	PSYSTEM_MODULE_INFORMATION system_modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, length, tag);
	if (!system_modules) return result;

	NTSTATUS status = ZwQuerySystemInformation(11, system_modules, length, 0);
	if (NT_SUCCESS(status))
	{
		for (unsigned long long i = 0; i < system_modules->ulModuleCount; i++)
		{
			PSYSTEM_MODULE mod = &system_modules->Modules[i];
			if (strstr(mod->ImageName, name))
			{
				result = (unsigned long long)mod->Base;
				if (size) *size = (unsigned long)mod->Size;
				break;
			}
		}
	}

	ExFreePoolWithTag(system_modules, tag);
	return result;
}

uint64_t Utils::fn_find_pattern(unsigned long long addr, unsigned long size, const char* pattern, const char* mask)
{
	size -= (unsigned long)strlen(mask);

	for (unsigned long i = 0; i < size; i++)
	{
		if (fn_pattern_check((const char*)addr + i, pattern, mask))
			return addr + i;
	}

	return 0;
}

unsigned long long Utils::fn_find_pattern_image(unsigned long long addr, const char* pattern, const char* mask, const char* name)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(addr + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
	for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER p = &section[i];

		if (strstr((const char*)p->Name, name))
		{
			unsigned long long result = fn_find_pattern(addr + p->VirtualAddress, p->Misc.VirtualSize, pattern, mask);
			if (result) return result;
		}
	}

	return 0;
}

unsigned long long Utils::fn_get_image_address(unsigned long long addr, const char* name, unsigned long* size)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(addr + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
	for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER p = &section[i];

		if (strstr((const char*)p->Name, name))
		{
			if (size) *size = p->SizeOfRawData;
			return (unsigned long long)p + p->VirtualAddress;
		}
	}

	return 0;
}

POBJECT_TYPE Utils::fn_get_type_by_name(wchar_t* name)
{


	PULONG64 table = (PULONG64)fn_get_index_table();//ͨ����������ObGetObjectType��ȡ�������ͱ�(win10������ObTypeIndexTable win7û����)
	if (!table) return NULL;

	UNICODE_STRING tName = { 0 };
	RtlInitUnicodeString(&tName, name);
	PMOBJECT_TYPE retObjType = NULL;

	for (int i = 0; i < 0xFF; i++)
	{
		PMOBJECT_TYPE type = (PMOBJECT_TYPE)table[i];
		if (type && MmIsAddressValid(type))
		{

			if (RtlCompareUnicodeString(&type->Name, &tName, TRUE) == 0)
			{
				retObjType = type;
				break;
			}
		}

	}

	return (POBJECT_TYPE)retObjType;
}

uint32_t Utils::fn_get_ssdt_index_by_name(char* name)
{
	NTSTATUS Status;
	HANDLE FileHandle;
	IO_STATUS_BLOCK ioStatus;
	FILE_STANDARD_INFORMATION FileInformation;
	//����NTDLL·��
	UNICODE_STRING uniFileName;
	RtlInitUnicodeString(&uniFileName, L"\\SystemRoot\\system32\\ntdll.dll");

	//��ʼ�����ļ�������
	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, &uniFileName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	//�����ļ�

	Status = IoCreateFile(&FileHandle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &objectAttributes,
		&ioStatus, 0, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
	if (!NT_SUCCESS(Status))
		return 0;
	//��ȡ�ļ���Ϣ

	Status = ZwQueryInformationFile(FileHandle, &ioStatus, &FileInformation,
		sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(Status)) {
		ZwClose(FileHandle);
		return 0;
	}
	//�ж��ļ���С�Ƿ����
	if (FileInformation.EndOfFile.HighPart != 0) {
		ZwClose(FileHandle);
		return 0;
	}
	//ȡ�ļ���С
	ULONG uFileSize = FileInformation.EndOfFile.LowPart;


	//�����ڴ�
	PVOID pBuffer = ExAllocatePoolWithTag(PagedPool, (ULONG64)uFileSize + 0x100, 0);
	if (pBuffer == NULL) {
		ZwClose(FileHandle);
		return 0;
	}

	//��ͷ��ʼ��ȡ�ļ�
	LARGE_INTEGER byteOffset;
	byteOffset.LowPart = 0;
	byteOffset.HighPart = 0;
	Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &ioStatus, pBuffer, uFileSize, &byteOffset, NULL);
	if (!NT_SUCCESS(Status)) {
		ZwClose(FileHandle);
		return 0;
	}
	//ȡ��������
	PIMAGE_DOS_HEADER  pDosHeader;
	PIMAGE_NT_HEADERS  pNtHeaders;
	PIMAGE_SECTION_HEADER pSectionHeader;
	ULONGLONG     FileOffset;//������64λ���ģ��������ﲻ��32���ֽ�
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	//DLL�ڴ�����ת��DOSͷ�ṹ
	pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	//ȡ��PEͷ�ṹ
	pNtHeaders = (PIMAGE_NT_HEADERS)((ULONGLONG)pBuffer + pDosHeader->e_lfanew);
	//�ж�PEͷ��������Ƿ�Ϊ��


	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
		return 0;

	//ȡ��������ƫ��
	FileOffset = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	//ȡ����ͷ�ṹ
	pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONGLONG)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER pOldSectionHeader = pSectionHeader;
	//�����ڽṹ���е�ַ����
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++) {
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= (ULONG64)(pSectionHeader->VirtualAddress) + (ULONG64)(pSectionHeader->SizeOfRawData))
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
	}

	//�������ַ
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONGLONG)pBuffer + FileOffset);
	//ȡ������������ַ
	PULONG AddressOfFunctions;
	FileOffset = pExportDirectory->AddressOfFunctions;
	//�����ڽṹ���е�ַ����
	pSectionHeader = pOldSectionHeader;
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++) {
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= (ULONG64)(pSectionHeader->VirtualAddress) + (ULONG64)(pSectionHeader->SizeOfRawData))
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
	}
	AddressOfFunctions = (PULONG)((ULONGLONG)pBuffer + FileOffset);//����ע��һ��foa��rva

	//ȡ��������������
	PUSHORT AddressOfNameOrdinals;
	FileOffset = pExportDirectory->AddressOfNameOrdinals;

	//�����ڽṹ���е�ַ����
	pSectionHeader = pOldSectionHeader;
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++) {
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= (ULONG64)(pSectionHeader->VirtualAddress) + (ULONG64)(pSectionHeader->SizeOfRawData))
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
	}
	AddressOfNameOrdinals = (PUSHORT)((ULONGLONG)pBuffer + FileOffset);//ע��һ��foa��rva

	//ȡ�������������
	PULONG AddressOfNames;
	FileOffset = pExportDirectory->AddressOfNames;

	//�����ڽṹ���е�ַ����
	pSectionHeader = pOldSectionHeader;
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++) {
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= (ULONG64)(pSectionHeader->VirtualAddress) + (ULONG64)(pSectionHeader->SizeOfRawData))
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
	}
	AddressOfNames = (PULONG)((ULONGLONG)pBuffer + FileOffset);//ע��һ��foa��rva

	//DbgPrint("\n AddressOfFunctions %llX AddressOfNameOrdinals %llX AddressOfNames %llX  \n", (ULONGLONG)AddressOfFunctions- (ULONGLONG)pBuffer, (ULONGLONG)AddressOfNameOrdinals- (ULONGLONG)pBuffer, (ULONGLONG)AddressOfNames- (ULONGLONG)pBuffer);
	//DbgPrint("\n AddressOfFunctions %llX AddressOfNameOrdinals %llX AddressOfNames %llX  \n", pExportDirectory->AddressOfFunctions, pExportDirectory->AddressOfNameOrdinals, pExportDirectory->AddressOfNames);

	//����������
	ULONG uNameOffset = 0;
	ULONG uOffset = 0;
	LPSTR FunName;
	PVOID pFuncAddr;
	ULONG uServerIndex;
	ULONG uAddressOfNames;
	for (ULONG uIndex = 0; uIndex < pExportDirectory->NumberOfNames; uIndex++, AddressOfNames++, AddressOfNameOrdinals++) {
		uAddressOfNames = *AddressOfNames;
		pSectionHeader = pOldSectionHeader;
		for (UINT32 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++) {
			if (pSectionHeader->VirtualAddress <= uAddressOfNames && uAddressOfNames <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
				uOffset = uAddressOfNames - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
		FunName = (LPSTR)((ULONGLONG)pBuffer + uOffset);
		if (FunName[0] == 'Z' && FunName[1] == 'w') {
			pSectionHeader = pOldSectionHeader;
			uOffset = (ULONG)AddressOfFunctions[*AddressOfNameOrdinals];
			for (UINT32 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++) {
				if (pSectionHeader->VirtualAddress <= uOffset && uOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
					uNameOffset = uOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
			}
			pFuncAddr = (PVOID)((ULONGLONG)pBuffer + uNameOffset);
			uServerIndex = *(PULONG)((ULONGLONG)pFuncAddr + 4);
			FunName[0] = 'N';
			FunName[1] = 't';
			if (!_stricmp(FunName, (const char*)name)) {//���ָ���ı��
				ExFreePoolWithTag(pBuffer, 0);
				ZwClose(FileHandle);
				return uServerIndex;
			}
		}
	}

	ExFreePoolWithTag(pBuffer, 0);
	ZwClose(FileHandle);
	return 0;
}

UINT64 Utils::fn_get_func_from_ssdt(uint32_t idx)
{

	static bool first = true;

	if (first) {

		ssdt = (PSYSTEM_SERVICE_TABLE)fn_get_ssdt(fn_get_moudle_address("ntoskrnl.exe",0 ));
		first = false;
	}
	ULONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = (PULONG)ssdt->ServiceTableBase;
	dwtmp = ServiceTableBase[idx];
	dwtmp = dwtmp >> 4;
	return (ULONG64)dwtmp + (ULONG64)ServiceTableBase;
}

void* Utils::fn_get_ssdt(uint64_t ntos_base)
{
	if (!ntos_base) return nullptr;

	/*
	2018����ں�ҳ����벹�� https://bbs.pediy.com/thread-223805.htm
	û�в����Ļ�����KiSystemCall64
	*/
#define IA32_LSTAR_MSR 0xC0000082
	void* syscall_entry = (void*)__readmsr(IA32_LSTAR_MSR);

	// û�в�����,ֱ�ӷ���KiSystemCall64����
	unsigned long section_size = 0;
	unsigned long long KVASCODE = fn_get_image_address(ntos_base, "KVASCODE", &section_size);
	if (!KVASCODE) return syscall_entry;

	// KiSystemCall64������������,Ҳ��ֱ�ӷ���
	if (!(syscall_entry >= (void*)KVASCODE && syscall_entry < (void*)(KVASCODE + section_size))) return syscall_entry;

	// ������һ���Ǿ���KiSystemCall64Shadow,����򲹶���
	hde64s hde_info{ 0 };
	for (char* ki_system_service_user = (char*)syscall_entry; ; ki_system_service_user += hde_info.len)
	{
		// �����
		if (!hde64_disasm(ki_system_service_user, &hde_info)) break;

		// ����Ҫ����jmp
#define OPCODE_JMP_NEAR 0xE9
		if (hde_info.opcode != OPCODE_JMP_NEAR) continue;

		// ������KVASCODE�����ڵ�jmpָ��
		void* possible_syscall_entry = (void*)((long long)ki_system_service_user + (int)hde_info.len + (int)hde_info.imm.imm32);
		if (possible_syscall_entry >= (void*)KVASCODE && possible_syscall_entry < (void*)((unsigned long long)KVASCODE + section_size)) continue;

		// ����KiSystemServiceUser
		syscall_entry = possible_syscall_entry;
		break;
	}

	return syscall_entry;
}

bool Utils::fn_hook_by_address(void** ori_func_addr, void* target_func_addr)
{
	uint64_t break_bytes = 0;
	
	if (m_Instance->m_count >= 100) {

		fn_logger("hooks too many!", true, STATUS_TOO_MANY_NODES);
		return false;
	}

	void* hook_addr = *ori_func_addr;
	hde64s hde;
	while (break_bytes < 14) {

		hde64_disasm(hook_addr, &hde);

		break_bytes += hde.len;

	}

	//����ԭ��14�ֽ�
	auto& cur_count = m_Instance->m_count;
	auto& info = m_Instance->m_hook_info_table;
	info[cur_count].hook_pid=PsGetCurrentProcessId();
	info[cur_count].ori_hook_addr=hook_addr;
	info[cur_count].target_hook_addr = target_func_addr;
	memcpy(info->old_bytes, hook_addr, 14);

	//��ʼ���Ĵ�
	*ori_func_addr = fn_tramp_line_init(hook_addr, 14, info->old_bytes);
	
	unsigned char jmp_code[14] = { 0xff,0x25,0x0,0,0,0,0,0,0,0,0,0,0,0 };

	*(void**)(&jmp_code[6]) = target_func_addr;

	//auto irql = fn_wp_bit_off();
	
	//Hook
	memcpy(hook_addr, jmp_code, 14);

	//fn_wp_bit_on(irql);

	cur_count++;

	return true;
}

bool Utils::fn_remove_hook_by_address(void* ori_func_addr)
{

	
	for (int i = 0; i < this->m_count; i++) {

		if (this->m_hook_info_table[i].ori_hook_addr == ori_func_addr) {
			//Find
			auto& info = m_hook_info_table[i];

			memcpy(ori_func_addr, info.old_bytes, 14);
			info.target_hook_addr = 0;

			fn_logger("remove hook success", false, 0);

			return true;
		}

	}

	fn_logger("no target hook!",true,0);
	return false;
}

bool Utils::fn_pattern_check(const char* data, const char* pattern, const char* mask)
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

void Utils::fn_logger(const char* log_str, bool is_err, long err_code)
{
	if (is_err) DbgPrintEx(77, 0, "[utils.cpp]err:%s err_code :%x\r\n", log_str, err_code);
	else DbgPrintEx(77, 0, "[utils.cpp]info: %s\r\n", log_str);

}

KIRQL Utils::fn_wp_bit_off()
{

	//�ر�CR0
	auto irql = KeRaiseIrqlToDpcLevel();//�ر��߳��л�
	UINT64 Cr0 = __readcr0();
	Cr0 &= 0xfffffffffffeffff;
	__writecr0(Cr0);
	_disable();
	return irql;

}

void Utils::fn_wp_bit_on(KIRQL irql)
{
	//����CR0
	UINT64 Cr0 = __readcr0();
	Cr0 |= 0x10000;
	_enable();
	__writecr0(Cr0);
	KeLowerIrql(irql);
}

void* Utils::fn_tramp_line_init(void* ret_address,uint64_t break_bytes_count,unsigned char* break_bytes)
{
	const ULONG TrampLineBreakBytes = 20;

	


	unsigned char TrampLineCode[TrampLineBreakBytes] = {//push xxx mov  ret ��Ӱ���κμĴ���
	0x6A, 0x00, 0x3E, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,
	0x3E, 0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00, 0xC3
	};

	//���ƾ�����ת
	*((PUINT32)&TrampLineCode[6]) = (UINT32)(((uint64_t)ret_address + break_bytes_count) & 0XFFFFFFFF);
	*((PUINT32)&TrampLineCode[15]) = (UINT32)((((uint64_t)ret_address + break_bytes_count) >> 32) & 0XFFFFFFFF);

	auto& used = m_Instance->m_tramp_line_used;
	auto& tramp_line_base = m_Instance->m_tramp_line;

	//����ԭ�Ȼٵ����ֽ�
	RtlCopyMemory(tramp_line_base + used, break_bytes, break_bytes_count);
	RtlCopyMemory(tramp_line_base + used+break_bytes_count, TrampLineCode, sizeof(TrampLineCode));

	auto ret = tramp_line_base + used;
	used += TrampLineBreakBytes + break_bytes_count;
	
	return ret;
}

uintptr_t* Utils::fn_get_index_table()
{
	RTL_OSVERSIONINFOW version = { 0 };
	RtlGetVersion(&version);
	LARGE_INTEGER in = { 0 };
	PUCHAR typeAddr = 0;

	UNICODE_STRING funcName = { 0 };
	RtlInitUnicodeString(&funcName, L"ObGetObjectType");
	PUCHAR MyObGetObjectType = (PUCHAR)MmGetSystemRoutineAddress(&funcName);

	if (!MyObGetObjectType) return NULL;

	if (version.dwMajorVersion <= 6)
	{
		typeAddr = ((PUCHAR)MyObGetObjectType + 7);


	}
	else
	{
		typeAddr = ((PUCHAR)MyObGetObjectType + 0x1F);
	}

	if (!typeAddr) return NULL;

	in.QuadPart = (ULONG64)(typeAddr + 4);
	in.LowPart += *((PULONG)typeAddr);
	return (uintptr_t*)in.QuadPart;
}
