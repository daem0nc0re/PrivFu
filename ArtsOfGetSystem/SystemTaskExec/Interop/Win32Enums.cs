using System;

namespace SystemTaskExec.Interop
{
    [Flags]
    internal enum ACCESS_MASK : uint
    {
        None = 0,

        // For Token
        TokenAssignPrimary = 0x00000001,
        TokenDuplicate = 0x00000002,
        TokenImpersonate = 0x00000004,
        TokenQuery = 0x00000008,
        TokenQuerySource = 0x00000010,
        TokenAdjustPrivileges = 0x00000020,
        TokenAdjustGroups = 0x00000040,
        TokenAdjustDefault = 0x00000080,
        TokenAdjustSessionId = 0x00000100,
        TokenAllAccess = 0x000F01FF,
        TokenExecute = 0x00020000,
        TokenRead = 0x00020008,
        TokenWrite = 0x000200E0,

        // Standard and Generic Rights
        SpecificRightsAll = 0x0000FFFF,
        Delete = 0x00010000,
        ReadControl = 0x00020000,
        WriteDac = 0x00040000,
        WriteOwner = 0x00080000,
        StandardRightsRequired = 0x000F0000,
        Synchronize = 0x00100000,
        StandardRightsAll = 0x001F0000,
        MaximumAllowed = 0x02000000,
        GenericAll = 0x10000000,
        GenericExecute = 0x20000000,
        GenericWrite = 0x40000000,
        GenericRead = 0x80000000
    }

    internal enum BOOLEAN : byte
    {
        False = 0,
        True
    }

    internal enum LOGON_PROVIDER
    {
        Default = 0,
        Winnt35,
        Winnt40,
        Winnt50,
        Virtual
    }

    internal enum LOGON_TYPE
    {
        Interactive = 2,
        Network,
        Batch,
        Service,
        Unlock,
        NetworkClearText,
        NewCredentials
    }

    internal enum MANDATORY_LABEL_RID : uint
    {
        Untrust = 0x0000,
        Low = 0x1000,
        Medium = 0x2000,
        MediumPlus = 0x2100,
        High = 0x3000,
        System = 0x4000,
        Protected = 0x5000
    }

    [Flags]
    internal enum OBJECT_ATTRIBUTES_FLAGS : uint
    {
        None = 0x00000000,
        ProtectClose = 0x00000001,
        Inherit = 0x00000002,
        AuditObjectClose = 0x00000004,
        NoEightsUpgrade = 0x00000008,
        Permanent = 0x00000010,
        Exclusive = 0x00000020,
        CaseInsensitive = 0x00000040,
        OpenIf = 0x00000080,
        OpenLink = 0x00000100,
        KernelHandle = 0x00000200,
        ForceAccessCheck = 0x00000400,
        IgnoreImpersonatedDevicemap = 0x00000800,
        DontReparse = 0x00001000,
        ValieAttributes = 0x00001FF2
    }

    [Flags]
    internal enum PROCESS_CREATION_FLAGS : uint
    {
        None = 0x00000000,
        DebugProcess = 0x00000001,
        DebugOnlyThisProcess = 0x00000002,
        CreateSuspended = 0x00000004,
        DetachedProcess = 0x00000008,
        CreateNewConsole = 0x00000010,
        NormalPriorityClass = 0x00000020,
        IdlePriorityClass = 0x00000040,
        HighPriorityClass = 0x00000080,
        RealtimePriorityClass = 0x00000100,
        CreateNewProcessGroup = 0x00000200,
        CreateUnicodeEnvironment = 0x00000400,
        CreateSeparateWowVdm = 0x00000800,
        CreateSharedWowVdm = 0x00001000,
        CreateForceDos = 0x00002000,
        BelowNormalPriorityClass = 0x00004000,
        AboveNormalPriorityClass = 0x00008000,
        InheritParentAffinity = 0x00010000,
        InheritCallerPriority = 0x00020000, // Deprecated
        CreateProtectedProcess = 0x00040000,
        ExtendedStartupInfoPresent = 0x00080000,
        ProcessModeBackgroundBegin = 0x00100000,
        ProcessModeBackgroundEnd = 0x00200000,
        CreateSecureProcess = 0x00400000,
        CreateBreakawayFromJob = 0x01000000,
        CreatePreserveCodeAuthzLevel = 0x02000000,
        CreateDefaultErrorMode = 0x04000000,
        CreateNoWindow = 0x08000000,
        ProfileUser = 0x10000000,
        ProfileKernel = 0x20000000,
        ProfileServer = 0x40000000,
        CreateIgnoreSystemDefault = 0x80000000
    }

    [Flags]
    internal enum SE_GROUP_ATTRIBUTES : uint
    {
        Mandatory = 0x00000001,
        EnabledByDefault = 0x00000002,
        Enabled = 0x00000004,
        Owner = 0x00000008,
        UseForDenyOnly = 0x00000010,
        Integrity = 0x00000020,
        IntegrityEnabled = 0x00000040,
        Resource = 0x20000000,
        LogonId = 0xC0000000
    }

    [Flags]
    internal enum SE_PRIVILEGE_ATTRIBUTES : uint
    {
        Disabled = 0x00000000,
        EnabledByDefault = 0x00000001,
        Enabled = 0x00000002,
        Removed = 0x00000004,
        UsedForAccess = 0x80000000
    }

    internal enum SE_PRIVILEGE_ID : ulong
    {
        SeCreateTokenPrivilege = 2,
        SeAssignPrimaryTokenPrivilege,
        SeLockMemoryPrivilege,
        SeIncreaseQuotaPrivilege,
        SeMachineAccountPrivilege,
        SeTcbPrivilege,
        SeSecurityPrivilege,
        SeTakeOwnershipPrivilege,
        SeLoadDriverPrivilege,
        SeSystemProfilePrivilege,
        SeSystemtimePrivilege,
        SeProfileSingleProcessPrivilege,
        SeIncreaseBasePriorityPrivilege,
        SeCreatePagefilePrivilege,
        SeCreatePermanentPrivilege,
        SeBackupPrivilege,
        SeRestorePrivilege,
        SeShutdownPrivilege,
        SeDebugPrivilege,
        SeAuditPrivilege,
        SeSystemEnvironmentPrivilege,
        SeChangeNotifyPrivilege,
        SeRemoteShutdownPrivilege,
        SeUndockPrivilege,
        SeSyncAgentPrivilege,
        SeEnableDelegationPrivilege,
        SeManageVolumePrivilege,
        SeImpersonatePrivilege,
        SeCreateGlobalPrivilege,
        SeTrustedCredManAccessPrivilege,
        SeRelabelPrivilege,
        SeIncreaseWorkingSetPrivilege,
        SeTimeZonePrivilege,
        SeCreateSymbolicLinkPrivilege,
        SeDelegateSessionUserImpersonatePrivilege,
        MaximumCount
    }

    [Flags]
    internal enum SHOW_WINDOW_FLAGS : ushort
    {
        Hide = 0,
        ShowNormal = 1,
        Normal = 1,
        ShowMinimized = 2,
        ShowMaximized = 3,
        Maximize = 3,
        ShowNoActive = 4,
        Show = 5,
        Minimize = 6,
        ShowMinNoActive = 7,
        ShowNA = 8,
        Restore = 9,
        ShowDefault = 10,
        ForceMinimize = 11,
        Max = 11
    }

    internal enum THREADINFOCLASS
    {
        ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
        ThreadTimes, // q: KERNEL_USER_TIMES
        ThreadPriority, // s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
        ThreadBasePriority, // s: KPRIORITY
        ThreadAffinityMask, // s: KAFFINITY
        ThreadImpersonationToken, // s: HANDLE
        ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
        ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
        ThreadEventPair,
        ThreadQuerySetWin32StartAddress, // q: ULONG_PTR
        ThreadZeroTlsCell, // s: ULONG // TlsIndex // 10
        ThreadPerformanceCount, // q: LARGE_INTEGER
        ThreadAmILastThread, // q: ULONG
        ThreadIdealProcessor, // s: ULONG
        ThreadPriorityBoost, // qs: ULONG
        ThreadSetTlsArrayAddress, // s: ULONG_PTR // Obsolete
        ThreadIsIoPending, // q: ULONG
        ThreadHideFromDebugger, // q: BOOLEAN; s: void
        ThreadBreakOnTermination, // qs: ULONG
        ThreadSwitchLegacyState, // s: void // NtCurrentThread // NPX/FPU
        ThreadIsTerminated, // q: ULONG // 20
        ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
        ThreadIoPriority, // qs: IO_PRIORITY_HINT (requires SeIncreaseBasePriorityPrivilege)
        ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
        ThreadPagePriority, // qs: PAGE_PRIORITY_INFORMATION
        ThreadActualBasePriority, // s: LONG (requires SeIncreaseBasePriorityPrivilege)
        ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
        ThreadCSwitchMon, // Obsolete
        ThreadCSwitchPmu,
        ThreadWow64Context, // qs: WOW64_CONTEXT, ARM_NT_CONTEXT since 20H1
        ThreadGroupInformation, // qs: GROUP_AFFINITY // 30
        ThreadUmsInformation, // q: THREAD_UMS_INFORMATION // Obsolete
        ThreadCounterProfiling, // q: BOOLEAN; s: THREAD_PROFILING_INFORMATION?
        ThreadIdealProcessorEx, // qs: PROCESSOR_NUMBER; s: previous PROCESSOR_NUMBER on return
        ThreadCpuAccountingInformation, // q: BOOLEAN; s: HANDLE (NtOpenSession) // NtCurrentThread // since WIN8
        ThreadSuspendCount, // q: ULONG // since WINBLUE
        ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
        ThreadContainerId, // q: GUID
        ThreadNameInformation, // qs: THREAD_NAME_INFORMATION
        ThreadSelectedCpuSets,
        ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
        ThreadActualGroupAffinity, // q: GROUP_AFFINITY // since THRESHOLD2
        ThreadDynamicCodePolicyInfo, // q: ULONG; s: ULONG (NtCurrentThread)
        ThreadExplicitCaseSensitivity, // qs: ULONG; s: 0 disables, otherwise enables
        ThreadWorkOnBehalfTicket, // RTL_WORK_ON_BEHALF_TICKET_EX
        ThreadSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
        ThreadDbgkWerReportActive, // s: ULONG; s: 0 disables, otherwise enables
        ThreadAttachContainer, // s: HANDLE (job object) // NtCurrentThread
        ThreadManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
        ThreadPowerThrottlingState, // POWER_THROTTLING_THREAD_STATE // since REDSTONE3 (set), WIN11 22H2 (query)
        ThreadWorkloadClass, // THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
        ThreadCreateStateChange, // since WIN11
        ThreadApplyStateChange,
        ThreadStrongerBadHandleChecks, // since 22H1
        ThreadEffectiveIoPriority, // q: IO_PRIORITY_HINT
        ThreadEffectivePagePriority, // q: ULONG
        ThreadUpdateLockOwnership, // since 24H2
        ThreadSchedulerSharedDataSlot, // SCHEDULER_SHARED_DATA_SLOT_INFORMATION
        ThreadTebInformationAtomic, // THREAD_TEB_INFORMATION
        ThreadIndexInformation, // THREAD_INDEX_INFORMATION
        MaxThreadInfoClass
    }

    internal enum TOKEN_ELEVATION_TYPE
    {
        Default = 1,
        Full,
        Limited
    }

    internal enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,                        // q: TOKEN_USER, SE_TOKEN_USER
        TokenGroups,                          // q: TOKEN_GROUPS
        TokenPrivileges,                      // q: TOKEN_PRIVILEGES
        TokenOwner,                           // qs: TOKEN_OWNER
        TokenPrimaryGroup,                    // qs: TOKEN_PRIMARY_GROUP
        TokenDefaultDacl,                     // qs: TOKEN_DEFAULT_DACL
        TokenSource,                          // q: TOKEN_SOURCE
        TokenType,                            // q: TOKEN_TYPE
        TokenImpersonationLevel,              // q: SECURITY_IMPERSONATION_LEVEL
        TokenStatistics,                      // q: TOKEN_STATISTICS // 10
        TokenRestrictedSids,                  // q: TOKEN_GROUPS
        TokenSessionId,                       // qs: ULONG (requires SeTcbPrivilege)
        TokenGroupsAndPrivileges,             // q: TOKEN_GROUPS_AND_PRIVILEGES
        TokenSessionReference,                // s: ULONG (requires SeTcbPrivilege)
        TokenSandBoxInert,                    // q: ULONG
        TokenAuditPolicy,                     // qs: TOKEN_AUDIT_POLICY (requires SeSecurityPrivilege/SeTcbPrivilege)
        TokenOrigin,                          // qs: TOKEN_ORIGIN (requires SeTcbPrivilege)
        TokenElevationType,                   // q: TOKEN_ELEVATION_TYPE
        TokenLinkedToken,                     // qs: TOKEN_LINKED_TOKEN (requires SeCreateTokenPrivilege)
        TokenElevation,                       // q: TOKEN_ELEVATION // 20
        TokenHasRestrictions,                 // q: ULONG
        TokenAccessInformation,               // q: TOKEN_ACCESS_INFORMATION
        TokenVirtualizationAllowed,           // qs: ULONG (requires SeCreateTokenPrivilege)
        TokenVirtualizationEnabled,           // qs: ULONG
        TokenIntegrityLevel,                  // qs: TOKEN_MANDATORY_LABEL
        TokenUIAccess,                        // qs: ULONG (requires SeTcbPrivilege)
        TokenMandatoryPolicy,                 // qs: TOKEN_MANDATORY_POLICY (requires SeTcbPrivilege)
        TokenLogonSid,                        // q: TOKEN_GROUPS
        TokenIsAppContainer,                  // q: ULONG // since WIN8
        TokenCapabilities,                    // q: TOKEN_GROUPS // 30
        TokenAppContainerSid,                 // q: TOKEN_APPCONTAINER_INFORMATION
        TokenAppContainerNumber,              // q: ULONG
        TokenUserClaimAttributes,             // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenDeviceClaimAttributes,           // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenRestrictedUserClaimAttributes,   // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenRestrictedDeviceClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenDeviceGroups,                    // q: TOKEN_GROUPS
        TokenRestrictedDeviceGroups,          // q: TOKEN_GROUPS
        TokenSecurityAttributes,              // qs: TOKEN_SECURITY_ATTRIBUTES_[AND_OPERATION_]INFORMATION (requires SeTcbPrivilege)
        TokenIsRestricted,                    // q: ULONG // 40
        TokenProcessTrustLevel,               // q: TOKEN_PROCESS_TRUST_LEVEL // since WINBLUE
        TokenPrivateNameSpace,                // qs: ULONG (requires SeTcbPrivilege) // since THRESHOLD
        TokenSingletonAttributes,             // q: TOKEN_SECURITY_ATTRIBUTES_INFORMATION // since REDSTONE
        TokenBnoIsolation,                    // q: TOKEN_BNO_ISOLATION_INFORMATION // since REDSTONE2
        TokenChildProcessFlags,               // s: ULONG  (requires SeTcbPrivilege) // since REDSTONE3
        TokenIsLessPrivilegedAppContainer,    // q: ULONG // since REDSTONE5
        TokenIsSandboxed,                     // q: ULONG // since 19H1
        TokenIsAppSilo,                       // q: ULONG // since WIN11 22H2 // previously TokenOriginatingProcessTrustLevel // q: TOKEN_PROCESS_TRUST_LEVEL
        TokenLoggingInformation,              // q: TOKEN_LOGGING_INFORMATION // since 24H2
        TokenLearningMode,                    // q: // since 25H2
        MaxTokenInfoClass
    }

    internal enum TOKEN_TYPE
    {
        Primary = 1,
        Impersonation
    }

    internal enum WTS_CONNECTSTATE_CLASS
    {
        Active,
        Connected,
        ConnectQuery,
        Shadow,
        Disconnected,
        Idle,
        Listen,
        Reset,
        Down,
        Init
    }
}
