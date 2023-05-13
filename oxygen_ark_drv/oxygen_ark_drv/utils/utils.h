#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include <ntimage.h>
#include "hde64.h"
#pragma  warning(disable :4201)
#pragma  warning(disable :4996)

#define MAX_HOOK_COUNT 0x100

using uint64_t = unsigned long long;
using uint16_t = unsigned short;
using uint8_t = unsigned char;


typedef struct _SYSTEM_MODULE
{
	ULONG_PTR Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG_PTR ulModuleCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;


typedef struct _OBJECT_TYPE_INITIALIZER
{
	UINT16       Length;
	union
	{
		UINT8        ObjectTypeFlags;
		struct
		{
			UINT8        CaseInsensitive : 1;
			UINT8        UnnamedObjectsOnly : 1;
			UINT8        UseDefaultObject : 1;
			UINT8        SecurityRequired : 1;
			UINT8        MaintainHandleCount : 1;
			UINT8        MaintainTypeList : 1;
			UINT8        SupportsObjectCallbacks : 1;
		};
	};
	ULONG32      ObjectTypeCode;
	ULONG32      InvalidAttributes;
	struct _GENERIC_MAPPING GenericMapping;
	ULONG32      ValidAccessMask;
	ULONG32      RetainAccess;
	enum _POOL_TYPE PoolType;
	ULONG32      DefaultPagedPoolCharge;
	ULONG32      DefaultNonPagedPoolCharge;
	PVOID        DumpProcedure;
	PVOID        OpenProcedure;
	PVOID         CloseProcedure;
	PVOID         DeleteProcedure;
	PVOID         ParseProcedure;
	PVOID        SecurityProcedure;
	PVOID         QueryNameProcedure;
	PVOID         OkayToCloseProcedure;
}OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;
//OBJECT_TYPE基本没怎么变过
typedef struct _MOBJECT_TYPE
{
	struct _LIST_ENTRY TypeList;                                            //0x0
	struct _UNICODE_STRING Name;                                            //0x10
	VOID* DefaultObject;                                                    //0x20
	UCHAR Index;                                                            //0x28
	ULONG TotalNumberOfObjects;                                             //0x2c
	ULONG TotalNumberOfHandles;                                             //0x30
	ULONG HighWaterNumberOfObjects;                                         //0x34
	ULONG HighWaterNumberOfHandles;                                         //0x38
	struct _OBJECT_TYPE_INITIALIZER TypeInfo;                               //0x40
	EX_PUSH_LOCK TypeLock;                                          //0xb0
	ULONG Key;                                                              //0xb8
	struct _LIST_ENTRY CallbackList;                                        //0xc0
}MOBJECT_TYPE, * PMOBJECT_TYPE;

EXTERN_C NTSTATUS ZwQuerySystemInformation(
	DWORD32 systemInformationClass,
	PVOID systemInformation,
	ULONG systemInformationLength,
	PULONG returnLength);

typedef struct _HOOK_INFO_ {

	HANDLE hook_pid;
	void* ori_hook_addr;
	void* target_hook_addr;
	unsigned char old_bytes[14];//一般是FF 25 00 00 00 00  JMP 因此损坏14个字节 保存方便恢复

}HOOK_INFO,*PHOOK_INFO;

typedef struct _SYSTEM_SERVICE_TABLE {
	PVOID       ServiceTableBase;
	PVOID       ServiceCounterTableBase;
	ULONGLONG   NumberOfServices;
	PVOID       ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;


class Utils {


public:
	static Utils* m_Instance;
	static Utils* fn_get_instance();
	uint32_t fn_get_os_build_number();
	//获取指定获取系统模块的基质
	uint64_t fn_get_moudle_address(const char* name, unsigned long* size);
	uint64_t fn_find_pattern(unsigned long long addr, unsigned long size, const char* pattern, const char* mask);
	unsigned long long fn_find_pattern_image(unsigned long long addr, const char* pattern, const char* mask, const char* name = ".text");
	//获取镜像基质
	unsigned long long fn_get_image_address(unsigned long long addr, const char* name, unsigned long* size);
	//获取ObjectType通过名字
	POBJECT_TYPE fn_get_type_by_name(wchar_t* name);

	//通过name获取ssdt index
	uint32_t fn_get_ssdt_index_by_name(char* name);
	//通过index 获取ssdt func
	UINT64 fn_get_func_from_ssdt(uint32_t idx);
	
	//获取ssdt
	void* fn_get_ssdt(uint64_t ntos_base);

	//内核内联Hook(PG)
	bool fn_hook_by_address(void** ori_func_addr, void* target_func_addr);
	//移除内核内联Hook
	bool fn_remove_hook_by_address(void* ori_func_addr);
private:
	uint64_t m_count;
	uint8_t* m_tramp_line;//存放蹦床的 
	uint64_t m_tramp_line_used;

	HOOK_INFO m_hook_info_table[MAX_HOOK_COUNT];

	PSYSTEM_SERVICE_TABLE ssdt;
	//模式匹配
	bool fn_pattern_check(const char* data, const char* pattern, const char* mask);
	void fn_logger(const char* log_str, bool is_err, long err_code);
	KIRQL fn_wp_bit_off();//强制读写开启
	void fn_wp_bit_on(KIRQL irql);
	void* fn_tramp_line_init(void* ret_address, uint64_t break_bytes_count, unsigned char* break_bytes);//初始化蹦床
	uintptr_t* fn_get_index_table();


};