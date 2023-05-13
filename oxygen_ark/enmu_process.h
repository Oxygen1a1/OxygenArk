#pragma once
#include <Windows.h>
//#include <ntdef.h>
#include <QDateTime>
#include <cstringt.h>
#include <stdlib.h>
#include "DriverLoad.h"
#include <tlhelp32.h>
#include <winternl.h>
#include <functional>



namespace process {

	typedef NTSTATUS(WINAPI* NtUserBuildHwndList_t)(
		HDESK hdesk,
		HWND hwndNext,
		BOOL fEnumChildren,
		BOOL RemoveImmersive,//ÒÆ³ý³Á½þÊ½´°¿Ú
		DWORD idThread,
		UINT cHwndMax,
		HWND* phwndFirst,
		PUINT pcHwndNeeded);

	typedef enum _PROCESSINFOCLASS {
		ProcessBasicInformation,
		ProcessQuotaLimits,
		ProcessIoCounters,
		ProcessVmCounters,
		ProcessTimes,
		ProcessBasePriority,
		ProcessRaisePriority,
		ProcessDebugPort,
		ProcessExceptionPort,
		ProcessAccessToken,
		ProcessLdtInformation,
		ProcessLdtSize,
		ProcessDefaultHardErrorMode,
		ProcessIoPortHandlers,          // Note: this is kernel mode only
		ProcessPooledUsageAndLimits,
		ProcessWorkingSetWatch,
		ProcessUserModeIOPL,
		ProcessEnableAlignmentFaultFixup,
		ProcessPriorityClass,
		ProcessWx86Information,
		ProcessHandleCount,
		ProcessAffinityMask,
		ProcessPriorityBoost,
		ProcessDeviceMap,
		ProcessSessionInformation,
		ProcessForegroundInformation,
		ProcessWow64Information,
		ProcessImageFileName,
		ProcessLUIDDeviceMapsEnabled,
		ProcessBreakOnTermination,
		ProcessDebugObjectHandle,
		ProcessDebugFlags,
		ProcessHandleTracing,
		ProcessIoPriority,
		ProcessExecuteFlags,
		ProcessResourceManagement,
		ProcessCookie,
		ProcessImageInformation,
		MaxProcessInfoClass             // MaxProcessInfoClass should always be the last enum
	} PROCESSINFOCLASS;


	typedef enum _SYSTEM_INFORMATION_CLASS {
		SystemBasicInformation,
		SystemProcessorInformation,             // obsolete...delete
		SystemPerformanceInformation,
		SystemTimeOfDayInformation,
		SystemPathInformation,
		SystemProcessInformation,
		SystemCallCountInformation,
		SystemDeviceInformation,
		SystemProcessorPerformanceInformation,
		SystemFlagsInformation,
		SystemCallTimeInformation,
		SystemModuleInformation,
		SystemLocksInformation,
		SystemStackTraceInformation,
		SystemPagedPoolInformation,
		SystemNonPagedPoolInformation,
		SystemHandleInformation,
		SystemObjectInformation,
		SystemPageFileInformation,
		SystemVdmInstemulInformation,
		SystemVdmBopInformation,
		SystemFileCacheInformation,
		SystemPoolTagInformation,
		SystemInterruptInformation,
		SystemDpcBehaviorInformation,
		SystemFullMemoryInformation,
		SystemLoadGdiDriverInformation,
		SystemUnloadGdiDriverInformation,
		SystemTimeAdjustmentInformation,
		SystemSummaryMemoryInformation,
		SystemMirrorMemoryInformation,
		SystemPerformanceTraceInformation,
		SystemObsolete0,
		SystemExceptionInformation,
		SystemCrashDumpStateInformation,
		SystemKernelDebuggerInformation,
		SystemContextSwitchInformation,
		SystemRegistryQuotaInformation,
		SystemExtendServiceTableInformation,
		SystemPrioritySeperation,
		SystemVerifierAddDriverInformation,
		SystemVerifierRemoveDriverInformation,
		SystemProcessorIdleInformation,
		SystemLegacyDriverInformation,
		SystemCurrentTimeZoneInformation,
		SystemLookasideInformation,
		SystemTimeSlipNotification,
		SystemSessionCreate,
		SystemSessionDetach,
		SystemSessionInformation,
		SystemRangeStartInformation,
		SystemVerifierInformation,
		SystemVerifierThunkExtend,
		SystemSessionProcessInformation,
		SystemLoadGdiDriverInSystemSpace,
		SystemNumaProcessorMap,
		SystemPrefetcherInformation,
		SystemExtendedProcessInformation,
		SystemRecommendedSharedDataAlignment,
		SystemComPlusPackage,
		SystemNumaAvailableMemory,
		SystemProcessorPowerInformation,
		SystemEmulationBasicInformation,
		SystemEmulationProcessorInformation,
		SystemExtendedHandleInformation,
		SystemLostDelayedWriteInformation,
		SystemBigPoolInformation,
		SystemSessionPoolTagInformation,
		SystemSessionMappedViewInformation,
		SystemHotpatchInformation,
		SystemObjectSecurityMode,
		SystemWatchdogTimerHandler,
		SystemWatchdogTimerInformation,
		SystemLogicalProcessorInformation,
		SystemWow64SharedInformation,
		SystemRegisterFirmwareTableInformationHandler,
		SystemFirmwareTableInformation,
		SystemModuleInformationEx,
		SystemVerifierTriageInformation,
		SystemSuperfetchInformation,
		SystemMemoryListInformation,
		SystemFileCacheInformationEx,
		MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
	} SYSTEM_INFORMATION_CLASS;


	EXTERN_C NTSTATUS
		ZwQueryInformationProcess(
			__in HANDLE ProcessHandle,
			__in PROCESSINFOCLASS ProcessInformationClass,
			__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
			__in ULONG ProcessInformationLength,
			__out_opt PULONG ReturnLength
		);


	typedef LONG KPRIORITY;




	typedef struct _LSA_UNICODE_STRING
	{
		USHORT  Length;
		USHORT  MaximumLength;
		PWSTR   Buffer;
	}LSA_UNICODE_STRING, * PLSA_UNICODE_STRING;


	typedef LONG KPRIORITY;

	typedef enum _THREAD_STATE
	{
		StateInitialized,
		StateReady,
		StateRunning,
		StateStandby,
		StateTerminated,
		StateWait,
		StateTransition,
		StateUnknown
	}THREAD_STATE;

	typedef enum _KWAIT_REASON
	{
		Executive,
		FreePage,
		PageIn,
		PoolAllocation,
		DelayExecution,
		Suspended,
		UserRequest,
		WrExecutive,
		WrFreePage,
		WrPageIn,
		WrPoolAllocation,
		WrDelayExecution,
		WrSuspended,
		WrUserRequest,
		WrEventPair,
		WrQueue,
		WrLpcReceive,
		WrLpcReply,
		WrVertualMemory,
		WrPageOut,
		WrRendezvous,
		Spare2,
		Spare3,
		Spare4,
		Spare5,
		Spare6,
		WrKernel
	}KWAIT_REASON;




	typedef LONG KPRIORITY;

	typedef struct _VM_COUNTERS
	{
		ULONG PeakVirtualSize;
		ULONG VirtualSize;
		ULONG PageFaultCount;
		ULONG PeakWorkingSetSize;
		ULONG WorkingSetSize;
		ULONG QuotaPeakPagedPoolUsage;
		ULONG QuotaPagedPoolUsage;
		ULONG QuotaPeakNonPagedPoolUsage;
		ULONG QuotaNonPagedPoolUsage;
		ULONG PagefileUsage;
		ULONG PeakPagefileUsage;
	}VM_COUNTERS, * PVM_COUNTERS;

	typedef struct _SYSTEM_THREADS
	{
		LARGE_INTEGER KernelTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER CreateTime;
		ULONG         WaitTime;
		PVOID         StartAddress;
		CLIENT_ID     ClientId;
		KPRIORITY     Priority;
		KPRIORITY     BasePriority;
		ULONG         ContextSwitchCount;
		THREAD_STATE  State;
		KWAIT_REASON  WaitReason;
	}SYSTEM_THREADS, * PSYSTEM_THREADS;

	typedef struct _SYSTEM_PROCESS_INFORMATION {
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		LARGE_INTEGER SpareLi1;
		LARGE_INTEGER SpareLi2;
		LARGE_INTEGER SpareLi3;
		LARGE_INTEGER CreateTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER KernelTime;
		UNICODE_STRING ImageName;
		KPRIORITY BasePriority;
		HANDLE UniqueProcessId;
		HANDLE InheritedFromUniqueProcessId;
		ULONG HandleCount;
		ULONG SessionId;
		ULONG_PTR PageDirectoryBase;
		SIZE_T PeakVirtualSize;
		SIZE_T VirtualSize;
		ULONG PageFaultCount;
		SIZE_T PeakWorkingSetSize;
		SIZE_T WorkingSetSize;
		SIZE_T QuotaPeakPagedPoolUsage;
		SIZE_T QuotaPagedPoolUsage;
		SIZE_T QuotaPeakNonPagedPoolUsage;
		SIZE_T QuotaNonPagedPoolUsage;
		SIZE_T PagefileUsage;
		SIZE_T PeakPagefileUsage;
		SIZE_T PrivatePageCount;
		LARGE_INTEGER ReadOperationCount;
		LARGE_INTEGER WriteOperationCount;
		LARGE_INTEGER OtherOperationCount;
		LARGE_INTEGER ReadTransferCount;
		LARGE_INTEGER WriteTransferCount;
		LARGE_INTEGER OtherTransferCount;
	} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

	//0x18 bytes (sizeof)
	struct _CURDIR
	{
		UNICODE_STRING DosPath;                                         //0x0
		VOID* Handle;                                                           //0x10
	};
	//0x448 bytes (sizeof)

	//0x18 bytes (sizeof)
	struct _RTL_DRIVE_LETTER_CURDIR
	{
		USHORT Flags;                                                           //0x0
		USHORT Length;                                                          //0x2
		ULONG TimeStamp;                                                        //0x4
		UNICODE_STRING DosPath;                                                 //0x8
	};

	struct _RTL_USER_PROCESS_PARAMETERS
	{
		ULONG MaximumLength;                                                    //0x0
		ULONG Length;                                                           //0x4
		ULONG Flags;                                                            //0x8
		ULONG DebugFlags;                                                       //0xc
		VOID* ConsoleHandle;                                                    //0x10
		ULONG ConsoleFlags;                                                     //0x18
		VOID* StandardInput;                                                    //0x20
		VOID* StandardOutput;                                                   //0x28
		VOID* StandardError;                                                    //0x30
		_CURDIR CurrentDirectory;                                        //0x38
		UNICODE_STRING DllPath;                                         //0x50
		UNICODE_STRING ImagePathName;                                   //0x60
		UNICODE_STRING CommandLine;                                     //0x70
		VOID* Environment;                                                      //0x80
		ULONG StartingX;                                                        //0x88
		ULONG StartingY;                                                        //0x8c
		ULONG CountX;                                                           //0x90
		ULONG CountY;                                                           //0x94
		ULONG CountCharsX;                                                      //0x98
		ULONG CountCharsY;                                                      //0x9c
		ULONG FillAttribute;                                                    //0xa0
		ULONG WindowFlags;                                                      //0xa4
		ULONG ShowWindowFlags;                                                  //0xa8
		UNICODE_STRING WindowTitle;                                     //0xb0
		UNICODE_STRING DesktopInfo;                                     //0xc0
		UNICODE_STRING ShellInfo;                                       //0xd0
		UNICODE_STRING RuntimeData;                                     //0xe0
		struct _RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];                  //0xf0
		ULONGLONG EnvironmentSize;                                              //0x3f0
		ULONGLONG EnvironmentVersion;                                           //0x3f8
		VOID* PackageDependencyData;                                            //0x400
		ULONG ProcessGroupId;                                                   //0x408
		ULONG LoaderThreads;                                                    //0x40c
		UNICODE_STRING RedirectionDllName;                              //0x410
		UNICODE_STRING HeapPartitionName;                               //0x420
		ULONGLONG* DefaultThreadpoolCpuSetMasks;                                //0x430
		ULONG DefaultThreadpoolCpuSetMaskCount;                                 //0x438
		ULONG DefaultThreadpoolThreadMaximum;                                   //0x43c
		ULONG HeapMemoryTypeMask;                                               //0x440
	};
	//0x7d0 bytes (sizeof)
	typedef struct _PEB
	{
		UCHAR InheritedAddressSpace;                                            //0x0
		UCHAR ReadImageFileExecOptions;                                         //0x1
		UCHAR BeingDebugged;                                                    //0x2
		union
		{
			UCHAR BitField;                                                     //0x3
			struct
			{
				UCHAR ImageUsesLargePages : 1;                                    //0x3
				UCHAR IsProtectedProcess : 1;                                     //0x3
				UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
				UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
				UCHAR IsPackagedProcess : 1;                                      //0x3
				UCHAR IsAppContainer : 1;                                         //0x3
				UCHAR IsProtectedProcessLight : 1;                                //0x3
				UCHAR IsLongPathAwareProcess : 1;                                 //0x3
			};
		};
		UCHAR Padding0[4];                                                      //0x4
		VOID* Mutant;                                                           //0x8
		VOID* ImageBaseAddress;                                                 //0x10
		struct _PEB_LDR_DATA* Ldr;                                              //0x18
		struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x20
		VOID* SubSystemData;                                                    //0x28
		VOID* ProcessHeap;                                                      //0x30
		void* FastPebLock;                              //0x38
		union _SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
		VOID* IFEOKey;                                                          //0x48
		union
		{
			ULONG CrossProcessFlags;                                            //0x50
			struct
			{
				ULONG ProcessInJob : 1;                                           //0x50
				ULONG ProcessInitializing : 1;                                    //0x50
				ULONG ProcessUsingVEH : 1;                                        //0x50
				ULONG ProcessUsingVCH : 1;                                        //0x50
				ULONG ProcessUsingFTH : 1;                                        //0x50
				ULONG ProcessPreviouslyThrottled : 1;                             //0x50
				ULONG ProcessCurrentlyThrottled : 1;                              //0x50
				ULONG ProcessImagesHotPatched : 1;                                //0x50
				ULONG ReservedBits0 : 24;                                         //0x50
			};
		};
		UCHAR Padding1[4];                                                      //0x54
		union
		{
			VOID* KernelCallbackTable;                                          //0x58
			VOID* UserSharedInfoPtr;                                            //0x58
		};
		ULONG SystemReserved;                                                   //0x60
		ULONG AtlThunkSListPtr32;                                               //0x64
		VOID* ApiSetMap;                                                        //0x68
		ULONG TlsExpansionCounter;                                              //0x70
		UCHAR Padding2[4];                                                      //0x74
		void* TlsBitmap;                                          //0x78
		ULONG TlsBitmapBits[2];                                                 //0x80
		VOID* ReadOnlySharedMemoryBase;                                         //0x88
		VOID* SharedData;                                                       //0x90
		VOID** ReadOnlyStaticServerData;                                        //0x98
		VOID* AnsiCodePageData;                                                 //0xa0
		VOID* OemCodePageData;                                                  //0xa8
		VOID* UnicodeCaseTableData;                                             //0xb0
		ULONG NumberOfProcessors;                                               //0xb8
		ULONG NtGlobalFlag;                                                     //0xbc
		union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
		ULONGLONG HeapSegmentReserve;                                           //0xc8
		ULONGLONG HeapSegmentCommit;                                            //0xd0
		ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
		ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
		ULONG NumberOfHeaps;                                                    //0xe8
		ULONG MaximumNumberOfHeaps;                                             //0xec
		VOID** ProcessHeaps;                                                    //0xf0
		VOID* GdiSharedHandleTable;                                             //0xf8
		VOID* ProcessStarterHelper;                                             //0x100
		ULONG GdiDCAttributeList;                                               //0x108
		UCHAR Padding3[4];                                                      //0x10c
		struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
		ULONG OSMajorVersion;                                                   //0x118
		ULONG OSMinorVersion;                                                   //0x11c
		USHORT OSBuildNumber;                                                   //0x120
		USHORT OSCSDVersion;                                                    //0x122
		ULONG OSPlatformId;                                                     //0x124
		ULONG ImageSubsystem;                                                   //0x128
		ULONG ImageSubsystemMajorVersion;                                       //0x12c
		ULONG ImageSubsystemMinorVersion;                                       //0x130
		UCHAR Padding4[4];                                                      //0x134
		ULONGLONG ActiveProcessAffinityMask;                                    //0x138
		ULONG GdiHandleBuffer[60];                                              //0x140
		VOID(*PostProcessInitRoutine)();                                       //0x230
		struct _RTL_BITMAP* TlsExpansionBitmap;                                 //0x238
		ULONG TlsExpansionBitmapBits[32];                                       //0x240
		ULONG SessionId;                                                        //0x2c0
		UCHAR Padding5[4];                                                      //0x2c4
		union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
		union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
		VOID* pShimData;                                                        //0x2d8
		VOID* AppCompatInfo;                                                    //0x2e0
		UNICODE_STRING CSDVersion;                                      //0x2e8
		VOID* ActivationContextData;                 //0x2f8
		VOID* ProcessAssemblyStorageMap;                //0x300
		VOID** SystemDefaultActivationContextData;    //0x308
		VOID* SystemAssemblyStorageMap;                 //0x310
		ULONGLONG MinimumStackCommit;                                           //0x318
		VOID* SparePointers[2];                                                 //0x320
		VOID* PatchLoaderData;                                                  //0x330
		VOID* ChpeV2ProcessInfo;                         //0x338
		ULONG AppModelFeatureState;                                             //0x340
		ULONG SpareUlongs[2];                                                   //0x344
		USHORT ActiveCodePage;                                                  //0x34c
		USHORT OemCodePage;                                                     //0x34e
		USHORT UseCaseMapping;                                                  //0x350
		USHORT UnusedNlsField;                                                  //0x352
		VOID* WerRegistrationData;                                              //0x358
		VOID* WerShipAssertPtr;                                                 //0x360
		VOID* EcCodeBitMap;                                                     //0x368
		VOID* pImageHeaderHash;                                                 //0x370
		union
		{
			ULONG TracingFlags;                                                 //0x378
			struct
			{
				ULONG HeapTracingEnabled : 1;                                     //0x378
				ULONG CritSecTracingEnabled : 1;                                  //0x378
				ULONG LibLoaderTracingEnabled : 1;                                //0x378
				ULONG SpareTracingBits : 29;                                      //0x378
			};
		};
		UCHAR Padding6[4];                                                      //0x37c
		ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
		ULONGLONG TppWorkerpListLock;                                           //0x388
		struct _LIST_ENTRY TppWorkerpList;                                      //0x390
		VOID* WaitOnAddressHashTable[128];                                      //0x3a0
		VOID* TelemetryCoverageHeader;                                          //0x7a0
		ULONG CloudFileFlags;                                                   //0x7a8
		ULONG CloudFileDiagFlags;                                               //0x7ac
		CHAR PlaceholderCompatibilityMode;                                      //0x7b0
		CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
		VOID* LeapSecondData;                               //0x7b8
		union
		{
			ULONG LeapSecondFlags;                                              //0x7c0
			struct
			{
				ULONG SixtySecondEnabled : 1;                                     //0x7c0
				ULONG Reserved : 31;                                              //0x7c0
			};
		};
		ULONG NtGlobalFlag2;                                                    //0x7c4
		ULONGLONG ExtendedFeatureDisableMask;                                   //0x7c8
	}PEB, * PPEB;

	typedef struct _PROCESS_BASIC_INFORMATION {
		NTSTATUS ExitStatus;
		PPEB PebBaseAddress;
		ULONG_PTR AffinityMask;
		KPRIORITY BasePriority;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR InheritedFromUniqueProcessId;
	} PROCESS_BASIC_INFORMATION;



	EXTERN_C
		NTSYSAPI
		NTSTATUS
		NTAPI
		ZwQuerySystemInformation(
			__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
			__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
			__in ULONG SystemInformationLength,
			__out_opt PULONG ReturnLength
		);



#define PAGE_SIZE 0x1000
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)


#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

	enum process_info_index {
		name,
		pid,
		ppid,
		uaccess,
		filecontractor,
		sid,
		fpath,
		stime,
		cmdline
	};



	typedef struct  p_info_t {

		char name[MAX_PATH];
		DWORD pid;
		DWORD ppid;
		bool uaccess;
		char filecontractor[60];
		DWORD sid;
		wchar_t fpath[MAX_PATH];
		QDateTime stime;
		wchar_t cmdline[MAX_PATH];
	}p_info, * pp_info;

	typedef struct _thread_info_t {
		char tid[MAX_PATH];
		char startAddr[MAX_PATH];
		char priority[MAX_PATH];
		char ethread[MAX_PATH];
		char teb[MAX_PATH];
		char switchCount[MAX_PATH];
		char moduleName[MAX_PATH];
	}thread_info_t, * pthread_info_t;

	typedef struct _threads_info_t {
		int threadsCount;
		pthread_info_t info;
	}threads_info_t, * pthreads_info_t;


	typedef struct module_info_t {
		char path[MAX_PATH];
		char moduleStart[MAX_PATH];
		char moduleEnd[MAX_PATH];
		char companyName[MAX_PATH];
	}*pmodule_info_t;

	typedef struct modules_info_t {
		HANDLE pid;
		int moduleCount;
		pmodule_info_t modules;
	}*pmodules_info_t;

	typedef struct window_info_t {

		HWND hwnd;
		HANDLE pid;
		HANDLE tid;
		BOOL isVisible;
		char titile[MAX_PATH];
	}*pwindow_info_t;

	typedef struct windows_info_t {
		int count;
		pwindow_info_t infos;

	}*pwindows_info;


	typedef struct timer_info_t {
		void* timer_object;
		void* pfn;
		unsigned int elapse;
		char modules[MAX_PATH];
	}*ptimer_info_t;

	typedef struct timers_info_t {
		int count;
		ptimer_info_t infos;
	}*ptimers_info_t;

	typedef struct query_timers_t {

		HANDLE pid;
		ptimers_info_t timers_info;

	}*pquery_timers_t;

	typedef struct handle_info_t {
		UINT32 access;
		char handleType[MAX_PATH];
		char handleName[MAX_PATH];
		HANDLE handle;
		UINT_PTR handleObject;
		UINT32 ptrRef;
		UINT32 handleRef;
		BOOLEAN closeProtect;
	}*phandle_info_t;

	typedef struct handles_info_t {
		unsigned int count;
		phandle_info_t infos;
	}*phandles_info_t;

	typedef struct query_handle_t {
		HANDLE pid;
		phandles_info_t infos;
	}*pquery_handle_t;

	typedef struct inject_t {

		HANDLE pid;
		wchar_t dllPath[MAX_PATH];

	}*pinject_t;


	auto enmu_process(QList<p_info>& info_list)->void;
	auto query_process_info(pp_info info) -> bool;
	auto get_file_companyname(const wchar_t* full_path) -> wchar_t*;
	auto get_file_companyname(const char* full_path) -> char*;
	auto force_terminate(HANDLE pid) -> bool;
	auto query_threads_by_pid(HANDLE pid) -> pthreads_info_t;
	auto hide_process(HANDLE pid) -> bool;
	auto enum_modules(HANDLE pid) -> pmodules_info_t;
	auto enum_windows(HANDLE pid) -> pwindows_info;
	auto enum_timers(HANDLE pid) -> ptimers_info_t;
	auto enum_handles(HANDLE pid) -> phandles_info_t;
	auto inject(HANDLE pid, const wchar_t* dll_path) -> bool;
}