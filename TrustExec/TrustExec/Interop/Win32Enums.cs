using System;

namespace TrustExec.Interop
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

        // Service Control Manager
        SC_MANAGER_CONNECT = 0x00000001,
        SC_MANAGER_CREATE_SERVICE = 0x00000002,
        SC_MANAGER_ENUMERATE_SERVICE = 0x00000004,
        SC_MANAGER_LOCK = 0x00000008,
        SC_MANAGER_QUERY_LOCK_STATUS = 0x00000010,
        SC_MANAGER_MODIFY_BOOT_CONFIG = 0x00000020,
        SC_MANAGER_ALL_ACCESS = 0x000F003F,

        // Service
        SERVICE_QUERY_CONFIG = 0x00000001,
        SERVICE_CHANGE_CONFIG = 0x00000002,
        SERVICE_QUERY_STATUS = 0x00000004,
        SERVICE_ENUMERATE_DEPENDENTS = 0x00000008,
        SERVICE_START = 0x00000010,
        SERVICE_STOP = 0x00000020,
        SERVICE_PAUSE_CONTINUE = 0x00000040,
        SERVICE_INTERROGATE = 0x00000080,
        SERVICE_USER_DEFINED_CONTROL = 0x00000100,
        SERVICE_ALL_ACCESS = 0x000F01FF,

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

    [Flags]
    internal enum ACE_FLAGS : byte
    {
        None = 0x00,
        ObjectInherit = 0x01,
        ContainerInherit = 0x02,
        NoPropagateInherit = 0x04,
        InheritOnly = 0x08,
        Inherited = 0x10,
        FailedAccess = 0x40,
        SuccessfulAccess = 0x80
    }

    internal enum ACL_REVISION : byte
    {
        ACL_REVISION = 2,
        ACL_REVISION_DS = 4,
    }

    internal enum ACE_TYPE : byte
    {
        AccessAllowed,
        AccessDenied,
        SystemAudit,
        SystemAlarm,
        AccessAllowedCompound,
        AccessAllowedObject,
        AccessDeniedObject,
        SystemAuditObject,
        SystemAlarmObject,
        AccessAllowedCallback,
        AccessDeniedCallback,
        AccessAllowedCallbackObject,
        AccessDeniedCallbackObject,
        SystemAuditCallback,
        SystemAlarmCallback,
        SystemAuditCallbackObject,
        SystemAlarmCallbackObject,
        SystemMandatoryLabel,
        SystemResourceAttribute,
        SystemScopedPolicyId,
        SystemProcessTrustLabel,
        SystemAccessFilter,
        // ACCESS_MAX_MS_V5 = 0x15
    }

    internal enum BOOLEAN : byte
    {
        FALSE,
        TRUE
    }

    internal enum COMPUTER_NAME_FORMAT
    {
        NetBIOS,
        DnsHostname,
        DnsDomain,
        DnsFullyQualified,
        PhysicalNetBIOS,
        PhysicalDnsHostname,
        PhysicalDnsDomain,
        PhysicalDnsFullyQualified,
        Max
    }

    internal enum ERROR_CONTROL
    {
        IGNORE,
        NORMAL,
        SEVERE,
        CRITICAL
    }

    [Flags]
    internal enum LOGON_FLAGS : uint
    {
        NONE = 0x00000000,
        LOGON_WITH_PROFILE = 0x00000001,
        LOGON_NETCREDENTIALS_ONLY = 0x00000002
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

    internal enum LSA_SID_NAME_MAPPING_OPERATION_ERROR
    {
        Success,
        NonMappingError,
        NameCollision,
        SidCollision,
        DomainNotFound,
        DomainSidPrefixMismatch = 6,
        MappingNotFound = 7
    }

    internal enum LSA_SID_NAME_MAPPING_OPERATION_TYPE
    {
        Add,
        Remove,
        AddMultiple
    }

    internal enum MSV1_0_LOGON_SUBMIT_TYPE
    {
        InteractiveLogon = 2,
        Lm20Logon,
        NetworkLogon,
        SubAuthLogon,
        WorkstationUnlockLogon = 7,
        S4ULogon = 12,
        VirtualLogon = 82,
        NoElevationLogon = 83,
        LuidLogon = 84
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

    internal enum SC_ENUM_TYPE
    {
        PROCESS_INFO
    }

    internal enum SC_STATUS_TYPE
    {
        PROCESS_INFO = 0
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

    internal enum SECURITY_CONTEXT_TRACKING_MODE : byte
    {
        StaticTracking = 0,
        DynamicTracking
    }

    internal enum SECURITY_IMPERSONATION_LEVEL
    {
        Anonymous,
        Identification,
        Impersonation,
        Delegation
    }

    [Flags]
    internal enum SECURITY_INFORMATION : uint
    {
        OWNER_SECURITY_INFORMATION = 0x00000001,
        GROUP_SECURITY_INFORMATION = 0x00000002,
        DACL_SECURITY_INFORMATION = 0x00000004,
        SACL_SECURITY_INFORMATION = 0x00000008,
        LABEL_SECURITY_INFORMATION = 0x00000010,
        ATTRIBUTE_SECURITY_INFORMATION = 0x00000020,
        SCOPE_SECURITY_INFORMATION = 0x00000040,
        PROCESS_TRUST_LABEL_SECURITY_INFORMATION = 0x00000080,
        BACKUP_SECURITY_INFORMATION = 0x00010000,
        UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
        UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
        PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
        PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
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

    [Flags]
    internal enum SERVICE_ACCEPTED_CONTROLS : uint
    {
        NONE = 0x00000000,
        STOP = 0x00000001,
        PAUSE_CONTINUE = 0x00000002,
        SHUTDOWN = 0x00000004,
        PARAMCHANGE = 0x00000008,
        NETBINDCHANGE = 0x00000010,
        HARDWAREPROFILECHANGE = 0x00000020,
        POWEREVENT = 0x00000040,
        SESSIONCHANGE = 0x00000080,
        PRESHUTDOWN = 0x00000100,
        TIMECHANGE = 0x00000200,
        TRIGGEREVENT = 0x00000400,
        USERMODEREBOOT = 0x00000800
    }

    internal enum SERVICE_CONTROL
    {
        STOP = 0x00000001,
        PAUSE = 0x00000002,
        CONTINUE = 0x00000003,
        INTERROGATE = 0x00000004,
        SHUTDOWN = 0x00000005,
        PARAMCHANGE = 0x00000006,
        NETBINDADD = 0x00000007,
        NETBINDREMOVE = 0x00000008,
        NETBINDENABLE = 0x00000009,
        NETBINDDISABLE = 0x0000000A,
        DEVICEEVENT = 0x0000000B,
        HARDWAREPROFILECHANGE = 0x0000000C,
        POWEREVENT = 0x0000000D,
        SESSIONCHANGE = 0x0000000E,
        PRESHUTDOWN = 0x0000000F,
        TIMECHANGE = 0x00000010,
        TRIGGEREVENT = 0x00000020,
        LOWRESOURCES = 0x00000060,
        SYSTEMLOWRESOURCES = 0x00000061
    }

    internal enum SERVICE_CURRENT_STATE
    {
        STOPPED = 1,
        START_PENDING,
        STOP_PENDING,
        RUNNING,
        CONTINUE_PENDING,
        PAUSE_PENDING,
        PAUSED
    }

    [Flags]
    internal enum SERVICE_FLAG : uint
    {
        NONE = 0x00000000,
        RUNS_IN_SYSTEM_PROCESS = 0x00000001
    }

    internal enum SERVICE_STATE
    {
        ACTIVE = 1,
        INACTIVE,
        STATE_ALL
    }

    [Flags]
    internal enum SERVICE_TYPE : uint
    {
        KERNEL_DRIVER = 0x00000001,
        FILE_SYSTEM_DRIVER = 0x00000002,
        ADAPTER = 0x00000004,
        RECOGNIZER_DRIVER = 0x00000008,
        DRIVER = 0x0000000B,
        WIN32_OWN_PROCESS = 0x00000010,
        WIN32_SHARE_PROCESS = 0x00000020,
        WIN32 = 0x00000030,
        USER_SERVICE = 0x00000040,
        USER_OWN_PROCESS = 0x00000050,
        USER_SHARE_PROCESS = 0x00000060,
        USERSERVICE_INSTANCE = 0x00000080,
        INTERACTIVE_PROCESS = 0x00000100,
        PKG_SERVICE = 0x00000200,
        ALL = 0x000003FF
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
        User = 1,
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

    internal enum TOKEN_TYPE
    {
        Primary = 1,
        Impersonation
    }

    internal enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        MaxTokenInfoClass
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
