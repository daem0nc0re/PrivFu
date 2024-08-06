using System;

namespace S4ULogonShell.Interop
{
    [Flags]
    internal enum ACCESS_MASK : uint
    {
        NO_ACCESS = 0x00000000,

        // For Process
        PROCESS_TERMINATE = 0x00000001,
        PROCESS_CREATE_THREAD = 0x00000002,
        PROCESS_VM_OPERATION = 0x00000008,
        PROCESS_VM_READ = 0x00000010,
        PROCESS_VM_WRITE = 0x00000020,
        PROCESS_DUP_HANDLE = 0x00000040,
        PROCESS_CREATE_PROCESS = 0x000000080,
        PROCESS_SET_QUOTA = 0x00000100,
        PROCESS_SET_INFORMATION = 0x00000200,
        PROCESS_QUERY_INFORMATION = 0x00000400,
        PROCESS_SUSPEND_RESUME = 0x00000800,
        PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000,
        PROCESS_ALL_ACCESS = 0x001F0FFF,

        // For Thread
        THREAD_TERMINATE = 0x00000001,
        THREAD_SUSPEND_RESUME = 0x00000002,
        THREAD_GET_CONTEXT = 0x00000008,
        THREAD_SET_CONTEXT = 0x00000010,
        THREAD_QUERY_INFORMATION = 0x00000040,
        THREAD_SET_INFORMATION = 0x00000020,
        THREAD_SET_THREAD_TOKEN = 0x00000080,
        THREAD_IMPERSONATE = 0x00000100,
        THREAD_DIRECT_IMPERSONATION = 0x00000200,
        THREAD_SET_LIMITED_INFORMATION = 0x00000400,
        THREAD_QUERY_LIMITED_INFORMATION = 0x00000800,
        THREAD_RESUME = 0x00001000,
        THREAD_ALL_ACCESS = 0x001FFFFF,

        // For Token
        TOKEN_ASSIGN_PRIMARY = 0x00000001,
        TOKEN_DUPLICATE = 0x00000002,
        TOKEN_IMPERSONATE = 0x00000004,
        TOKEN_QUERY = 0x00000008,
        TOKEN_QUERY_SOURCE = 0x00000010,
        TOKEN_ADJUST_PRIVILEGES = 0x00000020,
        TOKEN_ADJUST_GROUPS = 0x00000040,
        TOKEN_ADJUST_DEFAULT = 0x00000080,
        TOKEN_ADJUST_SESSIONID = 0x00000100,
        TOKEN_ALL_ACCESS = 0x000F01FF,
        TOKEN_EXECUTE = 0x00020000,
        TOKEN_READ = 0x00020008,
        TOKEN_WRITE = 0x000200E0,

        // Standard and Generic Rights
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000,
        STANDARD_RIGHTS_WRITE = 0x00020000,
        STANDARD_RIGHTS_EXECUTE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000,
    }

    internal enum BOOLEAN : byte
    {
        FALSE = 0,
        TRUE
    }

    internal enum COMPUTER_NAME_FORMAT
    {
        ComputerNameNetBIOS,
        ComputerNameDnsHostname,
        ComputerNameDnsDomain,
        ComputerNameDnsFullyQualified,
        ComputerNamePhysicalNetBIOS,
        ComputerNamePhysicalDnsHostname,
        ComputerNamePhysicalDnsDomain,
        ComputerNamePhysicalDnsFullyQualified,
        ComputerNameMax
    }

    internal enum ERROR_CONTROL
    {
        IGNORE,
        NORMAL,
        SEVERE,
        CRITICAL
    }

    [Flags]
    internal enum FormatMessageFlags : uint
    {
        FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100,
        FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200,
        FORMAT_MESSAGE_FROM_STRING = 0x00000400,
        FORMAT_MESSAGE_FROM_HMODULE = 0x00000800,
        FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000,
        FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000
    }

    [Flags]
    internal enum JOB_OBJECT_LIMIT : uint
    {
        WORKINGSET = 0x00000001,
        PROCESS_TIME = 0x00000002,
        JOB_TIME = 0x00000004,
        ACTIVE_PROCESS = 0x00000008,
        AFFINITY = 0x00000010,
        PRIORITY_CLASS = 0x00000020,
        PRESERVE_JOB_TIME = 0x00000040,
        SCHEDULING_CLASS = 0x00000080,
        PROCESS_MEMORY = 0x00000100,
        JOB_MEMORY = 0x00000200,
        DIE_ON_UNHANDLED_EXCEPTION = 0x00000400,
        BREAKAWAY_OK = 0x00000800,
        SILENT_BREAKAWAY_OK = 0x00001000,
        KILL_ON_JOB_CLOSE = 0x00002000,
        SUBSET_AFFINITY = 0x00004000,
        JOB_MEMORY_LOW = 0x00008000,
        JOB_READ_BYTES = 0x00010000,
        JOB_WRITE_BYTES = 0x00020000,
        RATE_CONTROL = 0x00040000,
        IO_RATE_CONTROL = 0x00080000,
        NET_RATE_CONTROL = 0x00100000
    }

    internal enum JOBOBJECTINFOCLASS
    {
        JobObjectBasicAccountingInformation = 1, // JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
        JobObjectBasicLimitInformation = 2, // JOBOBJECT_BASIC_LIMIT_INFORMATION
        JobObjectBasicProcessIdList = 3, // JOBOBJECT_BASIC_PROCESS_ID_LIST
        JobObjectBasicUIRestrictions = 4, // JOBOBJECT_BASIC_UI_RESTRICTIONS
        JobObjectSecurityLimitInformation = 5, // JOBOBJECT_SECURITY_LIMIT_INFORMATION
        JobObjectEndOfJobTimeInformation = 6, // JOBOBJECT_END_OF_JOB_TIME_INFORMATION
        JobObjectAssociateCompletionPortInformation = 7, // JOBOBJECT_ASSOCIATE_COMPLETION_PORT
        JobObjectBasicAndIoAccountingInformation = 8, // JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION
        JobObjectExtendedLimitInformation = 9, // JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        JobObjectJobSetInformation = 10, // JOBOBJECT_JOBSET_INFORMATION
        JobObjectGroupInformation = 11, // USHORT
        JobObjectNotificationLimitInformation = 12, // JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION
        JobObjectLimitViolationInformation = 13, // JOBOBJECT_LIMIT_VIOLATION_INFORMATION
        JobObjectGroupInformationEx = 14, // GROUP_AFFINITY (ARRAY)
        JobObjectCpuRateControlInformation = 15, // JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
        JobObjectCompletionFilter = 16,
        JobObjectCompletionCounter = 17,
        JobObjectFreezeInformation = 18, // JOBOBJECT_FREEZE_INFORMATION
        JobObjectExtendedAccountingInformation = 19, // JOBOBJECT_EXTENDED_ACCOUNTING_INFORMATION
        JobObjectWakeInformation = 20, // JOBOBJECT_WAKE_INFORMATION
        JobObjectBackgroundInformation = 21,
        JobObjectSchedulingRankBiasInformation = 22,
        JobObjectTimerVirtualizationInformation = 23,
        JobObjectCycleTimeNotification = 24,
        JobObjectClearEvent = 25,
        JobObjectInterferenceInformation = 26, // JOBOBJECT_INTERFERENCE_INFORMATION
        JobObjectClearPeakJobMemoryUsed = 27,
        JobObjectMemoryUsageInformation = 28, // JOBOBJECT_MEMORY_USAGE_INFORMATION // JOBOBJECT_MEMORY_USAGE_INFORMATION_V2
        JobObjectSharedCommit = 29,
        JobObjectContainerId = 30,
        JobObjectIoRateControlInformation = 31,
        JobObjectNetRateControlInformation = 32, // JOBOBJECT_NET_RATE_CONTROL_INFORMATION
        JobObjectNotificationLimitInformation2 = 33, // JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_2
        JobObjectLimitViolationInformation2 = 34, // JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2
        JobObjectCreateSilo = 35,
        JobObjectSiloBasicInformation = 36, // SILOOBJECT_BASIC_INFORMATION
        JobObjectSiloRootDirectory = 37, // SILOOBJECT_ROOT_DIRECTORY
        JobObjectServerSiloBasicInformation = 38, // SERVERSILO_BASIC_INFORMATION
        JobObjectServerSiloUserSharedData = 39, // SILO_USER_SHARED_DATA
        JobObjectServerSiloInitialize = 40,
        JobObjectServerSiloRunningState = 41,
        JobObjectIoAttribution = 42,
        JobObjectMemoryPartitionInformation = 43,
        JobObjectContainerTelemetryId = 44,
        JobObjectSiloSystemRoot = 45,
        JobObjectEnergyTrackingState = 46, // JOBOBJECT_ENERGY_TRACKING_STATE
        JobObjectThreadImpersonationInformation = 47,
        JobObjectIoPriorityLimit = 48,
        JobObjectPagePriorityLimit = 49,
        MaxJobObjectInfoClass = 50
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

    [Flags]
    internal enum LOGON_FLAGS : uint
    {
        NONE = 0x00000000,
        LOGON_WITH_PROFILE = 0x00000001,
        LOGON_NETCREDENTIALS_ONLY = 0x00000002
    }

    internal enum MSV1_0_LOGON_SUBMIT_TYPE
    {
        MsV1_0InteractiveLogon = 2,
        MsV1_0Lm20Logon,
        MsV1_0NetworkLogon,
        MsV1_0SubAuthLogon,
        MsV1_0WorkstationUnlockLogon = 7,
        MsV1_0S4ULogon = 12,
        MsV1_0VirtualLogon = 82,
        MsV1_0NoElevationLogon = 83,
        MsV1_0LuidLogon = 84
    }

    [Flags]
    internal enum OBJECT_ATTRIBUTES_FLAGS : uint
    {
        OBJ_INHERIT = 0x00000002,
        OBJ_PERMANENT = 0x00000010,
        OBJ_EXCLUSIVE = 0x00000020,
        OBJ_CASE_INSENSITIVE = 0x00000040,
        OBJ_OPENIF = 0x00000080,
        OBJ_OPENLINK = 0x00000100,
        OBJ_KERNEL_HANDLE = 0x00000200,
        OBJ_FORCE_ACCESS_CHECK = 0x00000400,
        OBJ_VALID_ATTRIBUTES = 0x000007f2
    }

    [Flags]
    internal enum PIPE_ACCESS : uint
    {
        INBOUND = 0x00000001,
        OUTBOUND = 0x00000002,
        DUPLEX = 0x00000003,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        FILE_FLAG_OVERLAPPED = 0x40000000,
        FILE_FLAG_WRITE_THROUGH = 0x80000000
    }

    internal enum PIPE_MODE
    {
        PIPE_WAIT = 0x00000000,
        PIPE_NOWAIT = 0x00000001,
        PIPE_READMODE_BYTE = 0x00000000,
        PIPE_READMODE_MESSAGE = 0x00000002,
        PIPE_TYPE_BYTE = 0x00000000,
        PIPE_TYPE_MESSAGE = 0x00000004,
        PIPE_ACCEPT_REMOTE_CLIENTS = 0x00000000,
        PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
    }

    [Flags]
    internal enum PROCESS_CREATION_FLAGS : uint
    {
        NONE = 0x00000000,
        DEBUG_PROCESS = 0x00000001,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        CREATE_SUSPENDED = 0x00000004,
        DETACHED_PROCESS = 0x00000008,
        CREATE_NEW_CONSOLE = 0x00000010,
        NORMAL_PRIORITY_CLASS = 0x00000020,
        IDLE_PRIORITY_CLASS = 0x00000040,
        HIGH_PRIORITY_CLASS = 0x00000080,
        REALTIME_PRIORITY_CLASS = 0x00000100,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_FORCEDOS = 0x00002000,
        BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
        ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
        INHERIT_PARENT_AFFINITY = 0x00010000,
        INHERIT_CALLER_PRIORITY = 0x00020000, // Deprecated
        CREATE_PROTECTED_PROCESS = 0x00040000,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
        PROCESS_MODE_BACKGROUND_END = 0x00200000,
        CREATE_SECURE_PROCESS = 0x00400000,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NO_WINDOW = 0x08000000,
        PROFILE_USER = 0x10000000,
        PROFILE_KERNEL = 0x20000000,
        PROFILE_SERVER = 0x40000000,
        CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000
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

    internal enum SE_PRIVILEGE_ID
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

    internal enum SECURITY_IMPERSONATION_LEVEL
    {
        Anonymous,
        Identification,
        Impersonation,
        Delegation
    }

    internal enum SECURITY_LOGON_TYPE
    {
        UndefinedLogonType = 0,
        Interactive = 2,
        Network,
        Batch,
        Service,
        Proxy,
        Unlock,
        NetworkCleartext,
        NewCredentials,
        RemoteInteractive,
        CachedInteractive,
        CachedRemoteInteractive,
        CachedUnlock
    }

    internal enum SERVICE_TYPE
    {
        KERNEL_DRIVER = 0x00000001,
        FILE_SYSTEM_DRIVER = 0x00000002,
        ADAPTER = 0x00000004,
        RECOGNIZER_DRIVER = 0x00000008,
        WIN32_OWN_PROCESS = 0x00000010,
        WIN32_SHARE_PROCESS = 0x00000020,
        INTERACTIVE_PROCESS = 0x00000100,
    }

    [Flags]
    internal enum SHOW_WINDOW_FLAGS : ushort
    {
        SW_HIDE = 0,
        SW_SHOWNORMAL = 1,
        SW_NORMAL = 1,
        SW_SHOWMINIMIZED = 2,
        SW_SHOWMAXIMIZED = 3,
        SW_MAXIMIZE = 3,
        SW_SHOWNOACTIVATE = 4,
        SW_SHOW = 5,
        SW_MINIMIZE = 6,
        SW_SHOWMINNOACTIVE = 7,
        SW_SHOWNA = 8,
        SW_RESTORE = 9,
        SW_SHOWDEFAULT = 10,
        SW_FORCEMINIMIZE = 11,
        SW_MAX = 11
    }

    internal enum SID_NAME_USE
    {
        Undefined = 0,
        User,
        Group,
        Domain,
        Alias,
        WellKnownGroup,
        DeletedAccount,
        Invalid,
        Unknown,
        Computer,
        Label,
        LogonSession
    }

    internal enum START_TYPE
    {
        BOOT_START,
        SYSTEM_START,
        AUTO_START,
        DEMAND_START,
        DISABLED
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

    internal enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1, // q: TOKEN_USER
        TokenGroups, // q: TOKEN_GROUPS
        TokenPrivileges, // q: TOKEN_PRIVILEGES
        TokenOwner, // q; s: TOKEN_OWNER
        TokenPrimaryGroup, // q; s: TOKEN_PRIMARY_GROUP
        TokenDefaultDacl, // q; s: TOKEN_DEFAULT_DACL
        TokenSource, // q: TOKEN_SOURCE
        TokenType, // q: TOKEN_TYPE
        TokenImpersonationLevel, // q: SECURITY_IMPERSONATION_LEVEL
        TokenStatistics, // q: TOKEN_STATISTICS // 10
        TokenRestrictedSids, // q: TOKEN_GROUPS
        TokenSessionId, // q; s: ULONG (requires SeTcbPrivilege)
        TokenGroupsAndPrivileges, // q: TOKEN_GROUPS_AND_PRIVILEGES
        TokenSessionReference, // s: ULONG (requires SeTcbPrivilege)
        TokenSandBoxInert, // q: ULONG
        TokenAuditPolicy, // q; s: TOKEN_AUDIT_POLICY (requires SeSecurityPrivilege/SeTcbPrivilege)
        TokenOrigin, // q; s: TOKEN_ORIGIN (requires SeTcbPrivilege)
        TokenElevationType, // q: TOKEN_ELEVATION_TYPE
        TokenLinkedToken, // q; s: TOKEN_LINKED_TOKEN (requires SeCreateTokenPrivilege)
        TokenElevation, // q: TOKEN_ELEVATION // 20
        TokenHasRestrictions, // q: ULONG
        TokenAccessInformation, // q: TOKEN_ACCESS_INFORMATION
        TokenVirtualizationAllowed, // q; s: ULONG (requires SeCreateTokenPrivilege)
        TokenVirtualizationEnabled, // q; s: ULONG
        TokenIntegrityLevel, // q; s: TOKEN_MANDATORY_LABEL
        TokenUIAccess, // q; s: ULONG
        TokenMandatoryPolicy, // q; s: TOKEN_MANDATORY_POLICY (requires SeTcbPrivilege)
        TokenLogonSid, // q: TOKEN_GROUPS
        TokenIsAppContainer, // q: ULONG
        TokenCapabilities, // q: TOKEN_GROUPS // 30
        TokenAppContainerSid, // q: TOKEN_APPCONTAINER_INFORMATION
        TokenAppContainerNumber, // q: ULONG
        TokenUserClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenDeviceClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenRestrictedUserClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenRestrictedDeviceClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenDeviceGroups, // q: TOKEN_GROUPS
        TokenRestrictedDeviceGroups, // q: TOKEN_GROUPS
        TokenSecurityAttributes, // q; s: TOKEN_SECURITY_ATTRIBUTES_[AND_OPERATION_]INFORMATION
        TokenIsRestricted, // q: ULONG // 40
        TokenProcessTrustLevel, // q: TOKEN_PROCESS_TRUST_LEVEL
        TokenPrivateNameSpace, // q; s: ULONG
        TokenSingletonAttributes, // q: TOKEN_SECURITY_ATTRIBUTES_INFORMATION
        TokenBnoIsolation, // q: TOKEN_BNO_ISOLATION_INFORMATION
        TokenChildProcessFlags, // s: ULONG
        TokenIsLessPrivilegedAppContainer, // q: ULONG
        TokenIsSandboxed, // q: ULONG
        TokenIsAppSilo, // TokenOriginatingProcessTrustLevel // q: TOKEN_PROCESS_TRUST_LEVEL
        MaxTokenInfoClass
    }

    internal enum TOKEN_TYPE
    {
        Primary = 1,
        Impersonation
    }

    [Flags]
    internal enum USER_FLAGS : uint
    {
        UF_SCRIPT = 0x00000001,
        UF_ACCOUNTDISABLE = 0x00000002,
        UF_HOMEDIR_REQUIRED = 0x00000008,
        UF_LOCKOUT = 0x00000010,
        UF_PASSWD_NOTREQD = 0x00000020,
        UF_PASSWD_CANT_CHANGE = 0x00000040,
        UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000080,
        UF_TEMP_DUPLICATE_ACCOUNT = 0x00000100,
        UF_NORMAL_ACCOUNT = 0x00000200,
        UF_INTERDOMAIN_TRUST_ACCOUNT = 0x00000800,
        UF_WORKSTATION_TRUST_ACCOUNT = 0x00001000,
        UF_SERVER_TRUST_ACCOUNT = 0x00002000,
        UF_DONT_EXPIRE_PASSWD = 0x00010000,
        UF_MNS_LOGON_ACCOUNT = 0x00020000,
        UF_SMARTCARD_REQUIRED = 0x00040000,
        UF_TRUSTED_FOR_DELEGATION = 0x00080000,
        UF_NOT_DELEGATED = 0x00100000,
        UF_USE_DES_KEY_ONLY = 0x00200000,
        UF_DONT_REQUIRE_PREAUTH = 0x00400000,
        UF_PASSWORD_EXPIRED = 0x00800000,
        UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000,
        UF_NO_AUTH_DATA_REQUIRED = 0x02000000,
        UF_PARTIAL_SECRETS_ACCOUNT = 0x04000000,
        UF_USE_AES_KEYS = 0x08000000
    }

    internal enum USER_INFO_FILTER
    {
        INTERDOMAIN_TRUST_ACCOUNT = 0x8,
        NORMAL_ACCOUNT = 0x2,
        PROXY_ACCOUNT = 0x4,
        SERVER_TRUST_ACCOUNT = 0x20,
        TEMP_DUPLICATE_ACCOUNT = 0x1,
        WORKSTATION_TRUST_ACCOUNT = 0x10
    }

    internal enum USER_PRIVS
    {
        GUEST,
        USER,
        ADMIN
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
