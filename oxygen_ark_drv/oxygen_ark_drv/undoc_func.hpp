#pragma once
#include "base.hpp"
//δ�ĵ����Ľṹ�� ����������
#pragma warning (disable : 4201)
namespace undoc{


	typedef struct _SYSTEM_THREAD_INFORMATION {
		LARGE_INTEGER Reserved1[3];
		ULONG Reserved2;
		PVOID StartAddress;
		CLIENT_ID ClientId;
		KPRIORITY Priority;
		LONG BasePriority;
		ULONG Reserved3;
		ULONG ThreadState;
		ULONG WaitReason;
	} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;
	//0x18 bytes (sizeof)
	struct _CURDIR
	{
		UNICODE_STRING DosPath;                                         //0x0
		VOID* Handle;                                                           //0x10
	};
	//0x448 bytes (sizeof)
	//0x120 bytes (sizeof)
	typedef struct LDR_DATA_TABLE_ENTRY
	{
		struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
		struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
		struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
		VOID* DllBase;                                                          //0x30
		VOID* EntryPoint;                                                       //0x38
		ULONG SizeOfImage;                                                      //0x40
		struct _UNICODE_STRING FullDllName;                                     //0x48
		struct _UNICODE_STRING BaseDllName;                                     //0x58
		union
		{
			UCHAR FlagGroup[4];                                                 //0x68
			ULONG Flags;                                                        //0x68
			struct
			{
				ULONG PackagedBinary : 1;                                         //0x68
				ULONG MarkedForRemoval : 1;                                       //0x68
				ULONG ImageDll : 1;                                               //0x68
				ULONG LoadNotificationsSent : 1;                                  //0x68
				ULONG TelemetryEntryProcessed : 1;                                //0x68
				ULONG ProcessStaticImport : 1;                                    //0x68
				ULONG InLegacyLists : 1;                                          //0x68
				ULONG InIndexes : 1;                                              //0x68
				ULONG ShimDll : 1;                                                //0x68
				ULONG InExceptionTable : 1;                                       //0x68
				ULONG ReservedFlags1 : 2;                                         //0x68
				ULONG LoadInProgress : 1;                                         //0x68
				ULONG LoadConfigProcessed : 1;                                    //0x68
				ULONG EntryProcessed : 1;                                         //0x68
				ULONG ProtectDelayLoad : 1;                                       //0x68
				ULONG ReservedFlags3 : 2;                                         //0x68
				ULONG DontCallForThreads : 1;                                     //0x68
				ULONG ProcessAttachCalled : 1;                                    //0x68
				ULONG ProcessAttachFailed : 1;                                    //0x68
				ULONG CorDeferredValidate : 1;                                    //0x68
				ULONG CorImage : 1;                                               //0x68
				ULONG DontRelocate : 1;                                           //0x68
				ULONG CorILOnly : 1;                                              //0x68
				ULONG ChpeImage : 1;                                              //0x68
				ULONG ReservedFlags5 : 2;                                         //0x68
				ULONG Redirected : 1;                                             //0x68
				ULONG ReservedFlags6 : 2;                                         //0x68
				ULONG CompatDatabaseProcessed : 1;                                //0x68
			};
		};
		USHORT ObsoleteLoadCount;                                               //0x6c
		USHORT TlsIndex;                                                        //0x6e
		struct _LIST_ENTRY HashLinks;                                           //0x70
		ULONG TimeDateStamp;                                                    //0x80
		VOID* EntryPointActivationContext;                //0x88
		VOID* Lock;                                                             //0x90
		VOID* DdagNode;                                        //0x98
		struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
		VOID* LoadContext;                                 //0xb0
		VOID* ParentDllBase;                                                    //0xb8
		VOID* SwitchBackContext;                                                //0xc0
		struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
		struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
		ULONGLONG OriginalBase;                                                 //0xf8
		union _LARGE_INTEGER LoadTime;                                          //0x100
		ULONG BaseNameHashValue;                                                //0x108
		ULONG  LoadReason;                                   //0x10c
		ULONG ImplicitPathOptions;                                              //0x110
		ULONG ReferenceCount;                                                   //0x114
		ULONG DependentLoadFlags;                                               //0x118
		UCHAR SigningLevel;                                                     //0x11c
	}*PLDR_DATA_TABLE_ENTRY;
	//0x18 bytes (sizeof)
	struct _RTL_DRIVE_LETTER_CURDIR
	{
		USHORT Flags;                                                           //0x0
		USHORT Length;                                                          //0x2
		ULONG TimeStamp;                                                        //0x4
		UNICODE_STRING DosPath;                                                 //0x8
	};
	//0x58 bytes (sizeof)
	struct _PEB_LDR_DATA
	{
		ULONG Length;                                                           //0x0
		UCHAR Initialized;                                                      //0x4
		VOID* SsHandle;                                                         //0x8
		struct _LIST_ENTRY InLoadOrderModuleList;                               //0x10
		struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x20
		struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x30
		VOID* EntryInProgress;                                                  //0x40
		UCHAR ShutdownInProgress;                                               //0x48
		VOID* ShutdownThreadId;                                                 //0x50
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
		_RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];                  //0xf0
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
		_RTL_BITMAP* TlsExpansionBitmap;                                 //0x238
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

	//0x38 bytes (sizeof)
	typedef struct _OBJECT_HEADER
	{
		LONGLONG PointerCount;                                                  //0x0
		union
		{
			LONGLONG HandleCount;                                               //0x8
			VOID* NextToFree;                                                   //0x8
		};
		VOID* Lock;                                              //0x10
		UCHAR TypeIndex;                                                        //0x18
		union
		{
			UCHAR TraceFlags;                                                   //0x19
			struct
			{
				UCHAR DbgRefTrace : 1;                                            //0x19
				UCHAR DbgTracePermanent : 1;                                      //0x19
			};
		};
		UCHAR InfoMask;                                                         //0x1a
		union
		{
			UCHAR Flags;                                                        //0x1b
			struct
			{
				UCHAR NewObject : 1;                                              //0x1b
				UCHAR KernelObject : 1;                                           //0x1b
				UCHAR KernelOnlyAccess : 1;                                       //0x1b
				UCHAR ExclusiveObject : 1;                                        //0x1b
				UCHAR PermanentObject : 1;                                        //0x1b
				UCHAR DefaultSecurityQuota : 1;                                   //0x1b
				UCHAR SingleHandleEntry : 1;                                      //0x1b
				UCHAR DeletedInline : 1;                                          //0x1b
			};
		};
		ULONG Reserved;                                                         //0x1c
		union
		{
			VOID* ObjectCreateInfo;                //0x20
			VOID* QuotaBlockCharged;                                            //0x20
		};
		VOID* SecurityDescriptor;                                               //0x28
		struct _QUAD Body;                                                      //0x30
	}OBJECT_HEADER, * POBJECT_HEADER;

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

	typedef LONG KPRIORITY;

	typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
		ULONG pid;
		UCHAR ObjectTypeIndex;
		UCHAR HandleAttributes;
		USHORT HandleValue;
		PVOID Object;
		ULONG GrantedAccess;
	} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

	typedef struct _SYSTEM_HANDLE_INFORMATION {
		ULONG NumberOfHandles;
		SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
	} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;



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

	typedef struct _CLIENT_ID
	{
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	}CLIENT_ID;
	typedef CLIENT_ID* PCLIENT_ID;

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



	typedef struct _PROCESS_BASIC_INFORMATION {
		NTSTATUS ExitStatus;
		PPEB PebBaseAddress;
		ULONG_PTR AffinityMask;
		KPRIORITY BasePriority;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR InheritedFromUniqueProcessId;
	} PROCESS_BASIC_INFORMATION;



	//0xa0 bytes (sizeof)
	typedef struct _KLDR_DATA_TABLE_ENTRY
	{
		struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
		VOID* ExceptionTable;                                                   //0x10
		ULONG ExceptionTableSize;                                               //0x18
		VOID* GpValue;                                                          //0x20
		struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;                        //0x28
		VOID* DllBase;                                                          //0x30
		VOID* EntryPoint;                                                       //0x38
		ULONG SizeOfImage;                                                      //0x40
		struct _UNICODE_STRING FullDllName;                                     //0x48
		struct _UNICODE_STRING BaseDllName;                                     //0x58
		ULONG Flags;                                                            //0x68
		USHORT LoadCount;                                                       //0x6c
		union
		{
			USHORT SignatureLevel : 4;                                            //0x6e
			USHORT SignatureType : 3;                                             //0x6e
			USHORT Unused : 9;                                                    //0x6e
			USHORT EntireField;                                                 //0x6e
		} u1;                                                                   //0x6e
		VOID* SectionPointer;                                                   //0x70
		ULONG CheckSum;                                                         //0x78
		ULONG CoverageSectionSize;                                              //0x7c
		VOID* CoverageSection;                                                  //0x80
		VOID* LoadedImports;                                                    //0x88
		VOID* Spare;                                                            //0x90
		ULONG SizeOfImageNotRounded;                                            //0x98
		ULONG TimeDateStamp;                                                    //0x9c
	}KLDR_DATA_TABLE_ENTRY,*PKLDR_DATA_TABLE_ENTRY;

	typedef enum _MOBJECT_INFORMATION_CLASS {
		ObjectBasicInformation,
		ObjectNameInformation,
		ObjectTypeInformation,
		ObjectTypesInformation,
		ObjectHandleFlagInformation,
	} MOBJECT_INFORMATION_CLASS;


	typedef struct _OBJECT_BASIC_INFORMATION {
		ULONG Attributes;
		ACCESS_MASK GrantedAccess;
		ULONG HandleCount;
		ULONG PointerCount;
		ULONG PagedPoolCharge;
		ULONG NonPagedPoolCharge;
		ULONG Reserved[3];
		ULONG NameInfoSize;
		ULONG TypeInfoSize;
		ULONG SecurityDescriptorSize;
		LARGE_INTEGER CreationTime;
	} OBJECT_BASIC_INFORMATION, * POBJECT_BASIC_INFORMATION;



	typedef struct _OBJECT_TYPE_INFORMATION {
		UNICODE_STRING TypeName;//��������
		ULONG TotalNumberOfObjects;
		ULONG TotalNumberOfHandles;
		ULONG TotalPagedPoolUsage;
		ULONG TotalNonPagedPoolUsage;
		ULONG TotalNamePoolUsage;
		ULONG TotalHandleTableUsage;
		ULONG HighWaterNumberOfObjects;
		ULONG HighWaterNumberOfHandles;
		ULONG HighWaterPagedPoolUsage;
		ULONG HighWaterNonPagedPoolUsage;
		ULONG HighWaterNamePoolUsage;
		ULONG HighWaterHandleTableUsage;
		ULONG InvalidAttributes;
		GENERIC_MAPPING GenericMapping;
		ULONG ValidAccessMask;
		BOOLEAN SecurityRequired;
		BOOLEAN MaintainHandleCount;
		ULONG PoolType;
		ULONG DefaultPagedPoolCharge;
		ULONG DefaultNonPagedPoolCharge;
	} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

	typedef struct _OBJECT_TYPES_INFORMATION {
		ULONG NumberOfTypes;//TypeIndex
		// OBJECT_TYPE_INFORMATION TypeInformation;
	} OBJECT_TYPES_INFORMATION, * POBJECT_TYPES_INFORMATION;

	typedef struct _OBJECT_HANDLE_FLAG_INFORMATION {
		BOOLEAN Inherit;
		BOOLEAN ProtectFromClose;//�ж��Ƿ���Թر�
	} OBJECT_HANDLE_FLAG_INFORMATION, * POBJECT_HANDLE_FLAG_INFORMATION;


	//0x480 bytes (sizeof)
	struct _PEB32
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
		ULONG Mutant;                                                           //0x4
		ULONG ImageBaseAddress;                                                 //0x8
		ULONG Ldr;                                                              //0xc
		ULONG ProcessParameters;                                                //0x10
		ULONG SubSystemData;                                                    //0x14
		ULONG ProcessHeap;                                                      //0x18
		ULONG FastPebLock;                                                      //0x1c
		ULONG AtlThunkSListPtr;                                                 //0x20
		ULONG IFEOKey;                                                          //0x24
		union
		{
			ULONG CrossProcessFlags;                                            //0x28
			struct
			{
				ULONG ProcessInJob : 1;                                           //0x28
				ULONG ProcessInitializing : 1;                                    //0x28
				ULONG ProcessUsingVEH : 1;                                        //0x28
				ULONG ProcessUsingVCH : 1;                                        //0x28
				ULONG ProcessUsingFTH : 1;                                        //0x28
				ULONG ProcessPreviouslyThrottled : 1;                             //0x28
				ULONG ProcessCurrentlyThrottled : 1;                              //0x28
				ULONG ProcessImagesHotPatched : 1;                                //0x28
				ULONG ReservedBits0 : 24;                                         //0x28
			};
		};
		union
		{
			ULONG KernelCallbackTable;                                          //0x2c
			ULONG UserSharedInfoPtr;                                            //0x2c
		};
		ULONG SystemReserved;                                                   //0x30
		ULONG AtlThunkSListPtr32;                                               //0x34
		ULONG ApiSetMap;                                                        //0x38
		ULONG TlsExpansionCounter;                                              //0x3c
		ULONG TlsBitmap;                                                        //0x40
		ULONG TlsBitmapBits[2];                                                 //0x44
		ULONG ReadOnlySharedMemoryBase;                                         //0x4c
		ULONG SharedData;                                                       //0x50
		ULONG ReadOnlyStaticServerData;                                         //0x54
		ULONG AnsiCodePageData;                                                 //0x58
		ULONG OemCodePageData;                                                  //0x5c
		ULONG UnicodeCaseTableData;                                             //0x60
		ULONG NumberOfProcessors;                                               //0x64
		ULONG NtGlobalFlag;                                                     //0x68
		union _LARGE_INTEGER CriticalSectionTimeout;                            //0x70
		ULONG HeapSegmentReserve;                                               //0x78
		ULONG HeapSegmentCommit;                                                //0x7c
		ULONG HeapDeCommitTotalFreeThreshold;                                   //0x80
		ULONG HeapDeCommitFreeBlockThreshold;                                   //0x84
		ULONG NumberOfHeaps;                                                    //0x88
		ULONG MaximumNumberOfHeaps;                                             //0x8c
		ULONG ProcessHeaps;                                                     //0x90
		ULONG GdiSharedHandleTable;                                             //0x94
		ULONG ProcessStarterHelper;                                             //0x98
		ULONG GdiDCAttributeList;                                               //0x9c
		ULONG LoaderLock;                                                       //0xa0
		ULONG OSMajorVersion;                                                   //0xa4
		ULONG OSMinorVersion;                                                   //0xa8
		USHORT OSBuildNumber;                                                   //0xac
		USHORT OSCSDVersion;                                                    //0xae
		ULONG OSPlatformId;                                                     //0xb0
		ULONG ImageSubsystem;                                                   //0xb4
		ULONG ImageSubsystemMajorVersion;                                       //0xb8
		ULONG ImageSubsystemMinorVersion;                                       //0xbc
		ULONG ActiveProcessAffinityMask;                                        //0xc0
		ULONG GdiHandleBuffer[34];                                              //0xc4
		ULONG PostProcessInitRoutine;                                           //0x14c
		ULONG TlsExpansionBitmap;                                               //0x150
		ULONG TlsExpansionBitmapBits[32];                                       //0x154
		ULONG SessionId;                                                        //0x1d4
		union _ULARGE_INTEGER AppCompatFlags;                                   //0x1d8
		union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x1e0
		ULONG pShimData;                                                        //0x1e8
		ULONG AppCompatInfo;                                                    //0x1ec
		struct _STRING32 CSDVersion;                                            //0x1f0
		ULONG ActivationContextData;                                            //0x1f8
		ULONG ProcessAssemblyStorageMap;                                        //0x1fc
		ULONG SystemDefaultActivationContextData;                               //0x200
		ULONG SystemAssemblyStorageMap;                                         //0x204
		ULONG MinimumStackCommit;                                               //0x208
		ULONG SparePointers[4];                                                 //0x20c
		ULONG SpareUlongs[5];                                                   //0x21c
		ULONG WerRegistrationData;                                              //0x230
		ULONG WerShipAssertPtr;                                                 //0x234
		ULONG pUnused;                                                          //0x238
		ULONG pImageHeaderHash;                                                 //0x23c
		union
		{
			ULONG TracingFlags;                                                 //0x240
			struct
			{
				ULONG HeapTracingEnabled : 1;                                     //0x240
				ULONG CritSecTracingEnabled : 1;                                  //0x240
				ULONG LibLoaderTracingEnabled : 1;                                //0x240
				ULONG SpareTracingBits : 29;                                      //0x240
			};
		};
		ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x248
		ULONG TppWorkerpListLock;                                               //0x250
		struct LIST_ENTRY32 TppWorkerpList;                                     //0x254
		ULONG WaitOnAddressHashTable[128];                                      //0x25c
		ULONG TelemetryCoverageHeader;                                          //0x45c
		ULONG CloudFileFlags;                                                   //0x460
		ULONG CloudFileDiagFlags;                                               //0x464
		CHAR PlaceholderCompatibilityMode;                                      //0x468
		CHAR PlaceholderCompatibilityModeReserved[7];                           //0x469
		ULONG LeapSecondData;                                                   //0x470
		union
		{
			ULONG LeapSecondFlags;                                              //0x474
			struct
			{
				ULONG SixtySecondEnabled : 1;                                     //0x474
				ULONG Reserved : 31;                                              //0x474
			};
		};
		ULONG NtGlobalFlag2;                                                    //0x478
	};


	EXTERN_C
		NTSTATUS
		ZwQueryInformationProcess(
			__in HANDLE ProcessHandle,
			__in PROCESSINFOCLASS ProcessInformationClass,
			__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
			__in ULONG ProcessInformationLength,
			__out_opt PULONG ReturnLength
		);

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

	EXTERN_C
		NTSTATUS
		NtQuerySystemInformation(
			IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
			OUT PVOID SystemInformation,
			IN ULONG SystemInformationLength,
			OUT PULONG ReturnLength OPTIONAL
		);
	EXTERN_C NTSTATUS
		ZwQueryInformationProcess(
			__in HANDLE ProcessHandle,
			__in PROCESSINFOCLASS ProcessInformationClass,
			__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
			__in ULONG ProcessInformationLength,
			__out_opt PULONG ReturnLength
		);
	EXTERN_C PPEB PsGetProcessPeb(__in PEPROCESS);
	EXTERN_C PVOID PsGetThreadTeb(__in PETHREAD);
	EXTERN_C _PEB32* PsGetProcessWow64Process(PEPROCESS process);
	EXTERN_C PPEB PsGetProcessPeb(PEPROCESS process);
	//moduleList �ں˵�
	EXTERN_C PLIST_ENTRY PsLoadedModuleList;
}