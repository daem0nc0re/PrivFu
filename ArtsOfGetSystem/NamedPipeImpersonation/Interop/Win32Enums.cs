using System;

namespace NamedPipeImpersonation.Interop
{
    [Flags]
    internal enum ACCESS_MASK : uint
    {
        NO_ACCESS = 0x00000000,

        // For Directory
        DIRECTORY_QUERY = 0x00000001,
        DIRECTORY_TRAVERSE = 0x00000002,
        DIRECTORY_CREATE_OBJECT = 0x00000004,
        DIRECTORY_CREATE_SUBDIRECTORY = 0x00000008,
        DIRECTORY_ALL_ACCESS = 0x000F000F,

        // For Process
        PROCESS_TERMINATE = 0x00000001,
        PROCESS_CREATE_THREAD = 0x00000002,
        PROCESS_SET_SESSIONID = 0x00000004,
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
        PROCESS_SET_LIMITED_INFORMATION = 0x00002000,
        PROCESS_ALL_ACCESS = 0x001FFFFF,

        // For Thread
        THREAD_TERMINATE = 0x00000001,
        THREAD_SUSPEND_RESUME = 0x00000002,
        THREAD_ALERT = 0x00000004,
        THREAD_GET_CONTEXT = 0x00000008,
        THREAD_SET_CONTEXT = 0x00000010,
        THREAD_SET_INFORMATION = 0x00000020,
        THREAD_QUERY_INFORMATION = 0x00000040,
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

        // For Files
        FILE_ANY_ACCESS = 0x00000000,
        FILE_READ_ACCESS = 0x00000001,
        FILE_WRITE_ACCESS = 0x00000002,
        FILE_READ_DATA = 0x00000001,
        FILE_LIST_DIRECTORY = 0x00000001,
        FILE_WRITE_DATA = 0x00000002,
        FILE_ADD_FILE = 0x00000002,
        FILE_APPEND_DATA = 0x00000004,
        FILE_ADD_SUBDIRECTORY = 0x00000004,
        FILE_CREATE_PIPE_INSTANCE = 0x00000004,
        FILE_READ_EA = 0x00000008,
        FILE_WRITE_EA = 0x00000010,
        FILE_EXECUTE = 0x00000020,
        FILE_TRAVERSE = 0x00000020,
        FILE_DELETE_CHILD = 0x00000040,
        FILE_READ_ATTRIBUTES = 0x00000080,
        FILE_WRITE_ATTRIBUTES = 0x00000100,
        FILE_ALL_ACCESS = 0x001F01FF,
        FILE_GENERIC_READ = 0x00100089,
        FILE_GENERIC_WRITE = 0x00100116,
        FILE_GENERIC_EXECUTE = 0x001000A0,

        // Job
        JOB_ASSIGN_PROCESS = 0x00000001,
        JOB_SET_ATTRIBUTES = 0x00000002,
        JOB_QUERY = 0x00000004,
        JOB_TERMINATE = 0x00000008,
        JOB_SET_SECURITY_ATTRIBUTES = 0x00000010,
        JOB_IMPERSONATE = 0x00000020,

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

        // Others
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
        SPECIFIC_RIGHTS_ALL = 0x0000FFFF,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000,
        DESKTOP_READOBJECTS = 0x00000001,
        DESKTOP_CREATEWINDOW = 0x00000002,
        DESKTOP_CREATEMENU = 0x00000004,
        DESKTOP_HOOKCONTROL = 0x00000008,
        DESKTOP_JOURNALRECORD = 0x00000010,
        DESKTOP_JOURNALPLAYBACK = 0x00000020,
        DESKTOP_ENUMERATE = 0x00000040,
        DESKTOP_WRITEOBJECTS = 0x00000080,
        DESKTOP_SWITCHDESKTOP = 0x00000100,
        WINSTA_ENUMDESKTOPS = 0x00000001,
        WINSTA_READATTRIBUTES = 0x00000002,
        WINSTA_ACCESSCLIPBOARD = 0x00000004,
        WINSTA_CREATEDESKTOP = 0x00000008,
        WINSTA_WRITEATTRIBUTES = 0x00000010,
        WINSTA_ACCESSGLOBALATOMS = 0x00000020,
        WINSTA_EXITWINDOWS = 0x00000040,
        WINSTA_ENUMERATE = 0x00000100,
        WINSTA_READSCREEN = 0x00000200,
        WINSTA_ALL_ACCESS = 0x0000037F,

        // For section
        SECTION_QUERY = 0x00000001,
        SECTION_MAP_WRITE = 0x00000002,
        SECTION_MAP_READ = 0x00000004,
        SECTION_MAP_EXECUTE = 0x00000008,
        SECTION_EXTEND_SIZE = 0x00000010,
        SECTION_MAP_EXECUTE_EXPLICIT = 0x00000020,
        SECTION_ALL_ACCESS = 0x000F001F
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
        MANDATORY = 0x00000001,
        ENABLED_BY_DEFAULT = 0x00000002,
        ENABLED = 0x00000004,
        OWNER = 0x00000008,
        USE_FOR_DENY_ONLY = 0x00000010,
        INTEGRITY = 0x00000020,
        INTEGRITY_ENABLED = 0x00000040,
        RESOURCE = 0x20000000,
        LOGON_ID = 0xC0000000
    }

    [Flags]
    internal enum SE_PRIVILEGE_ATTRIBUTES : uint
    {
        ENABLED_BY_DEFAULT = 0x00000001,
        ENABLED = 0x00000002,
        REMOVED = 0X00000004,
        USED_FOR_ACCESS = 0x80000000
    }

    internal enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
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
        TokenPrimary = 1,
        TokenImpersonation
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
}
