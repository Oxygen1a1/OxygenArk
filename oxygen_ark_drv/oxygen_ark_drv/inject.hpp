#pragma once
#include "base.hpp"
#include "_utils.hpp"
#pragma warning(disable : 4309)
#pragma warning(disable : 4838)
#pragma warning(disable : 4302)
#pragma warning(disable : 4311)
namespace inject{
#define MAX_PATH 260
	//48:83EC 30 | sub rsp, 30 |
	//B9 00000000 | mov ecx, 0 |
	//BA 00000000 | mov edx, 0 |
	//49 : B8 78563412785634 | mov r8, 1234567812345678 | r8 : &"吚x\n�|$@"
	//4C : 8D4C24 28 | lea r9, qword ptr ss : [rsp + 28] |
	//FF15 07000000 | call qword ptr ds : [7FFF0F30CECF] |
	//48 : 83C4 1E | add rsp, 1E |
	//33C0 | xor eax, eax |
	//C3 | ret |
	//0000000000000000 | dq 0 |

	inline char x64_shellcode[] = {
	0x48,0x83,0xEC,0x38,
	0xB9,0x00,0x00,0x00,0x00,
	0xBA,0x00,0x00,0x00,0x00,
	0x49,0xB8,0x78,0x56,0x34,0x12,0x78,0x56,0x34,0x12,
	0x4C,0x8D,0x4C,0x24,0x28,
	0xFF,0x15,0x07,0x00,0x00,0x00,
	0x48,0x83,0xC4,0x38,
	0x33,0xC0,
	0xC3,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	};

	//| 83EC 10 | sub esp, 50 |
	//| 6A 00 | push 0 |
	//| 8D4424 08 | lea eax, dword ptr ss : [esp + 20] |
	//| 890424 | mov dword ptr ss : [esp] , eax |
	//| 68 78563412 | push 12345678 |
	//| 6A 00 | push 0 |
	//| 6A 00 | push 0 |
	//| B8 78563412 | mov eax, 12345678 |
	//| FFD0 | call eax |
	//| 83C4 0A | add esp, 50 |
	//| 33C0 | xor eax, eax |
	//| C3 | ret |
	inline char x86_shellcode[] = {
		0x83,0xEC,0x50,
		0x6A,0x00,
		0x8D,0x44,0x24,0x20,
		0x89,0x04,0x24,
		0x68,0x78,0x56,0x34,0x12, //UNICODE_STRING*
		0x6A,0x00,
		0x6A,0x00,
		0xB8,0x78,0x56,0x34,0x12,
		0xFF,0xD0,
		0x83,0xC4,0x50,
		0x33,0xC0,
		0xC3
	};
#pragma pack(push)
#pragma pack(1)
	typedef struct x64_shellcode_t {
		char padding[16];
		UNICODE_STRING* dllPath;
		char padding02[18];
		UINT_PTR LdrLoadDll;
	}*px64_shellcode_t;

	typedef struct x86_shellcode_t {
		char padding[13];
		ULONG dllPath;//x86指针
		char paddin02[5];
		ULONG LdrLoadDll;//
		char padding02[8];
	}*px86_shellcode_t;
#pragma pack(pop)


	//0x8 bytes (sizeof) x86的这个要手动弄
	typedef struct UNICODE_STRING_x86
	{
		USHORT Length;                                                          //0x0
		USHORT MaximumLength;                                                   //0x2
		ULONG Buffer;                                                          //0x4
	}*PUNICODE_STRING_x86;

	typedef struct inject_t {

		HANDLE pid;
		wchar_t dllPath[MAX_PATH];

	}*pinject_t;

	auto inject_x86(PEPROCESS process,const wchar_t* dll_path) -> bool;

	auto inject_x64(PEPROCESS process, const wchar_t* dll_path) -> bool;

	typedef NTSTATUS(NTAPI* fnNtCreateThreadEx)
		(
			PHANDLE ThreadHandle,
			ACCESS_MASK DesiredAccess,
			PVOID ObjectAttributes,
			HANDLE ProcessHandle,
			PVOID StartAddress,
			PVOID Parameter,
			ULONG Flags,
			SIZE_T StackZeroBits,
			SIZE_T SizeOfStackCommit,
			SIZE_T SizeOfStackReserve,
			PVOID ByteBuffer);
}
