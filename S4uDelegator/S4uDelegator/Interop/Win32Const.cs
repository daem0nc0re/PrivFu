using System;

namespace S4uDelegator.Interop
{
    class Win32Const
    {
        public enum COMPUTER_NAME_FORMAT
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

        [Flags]
        public enum FormatMessageFlags : uint
        {
            FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100,
            FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200,
            FORMAT_MESSAGE_FROM_STRING = 0x00000400,
            FORMAT_MESSAGE_FROM_HMODULE = 0x00000800,
            FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000,
            FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            PROCESS_ALL_ACCESS = 0x001F0FFF,
            Terminate = 0x00000001,
            PROCESS_CREATE_THREAD = 0x00000002,
            PROCESS_VM_OPERATION = 0x00000008,
            PROCESS_VM_READ = 0x00000010,
            PROCESS_VM_WRITE = 0x00000020,
            PROCESS_DUP_HANDLE = 0x00000040,
            PROCESS_CREATE_PROCESS = 0x000000080,
            PROCESS_SET_QUOTA = 0x00000100,
            PROCESS_SET_INFORMATION = 0x00000200,
            PROCESS_QUERY_INFORMATION = 0x00000400,
            PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000,
            SYNCHRONIZE = 0x00100000,
            MAXIMUM_ALLOWED = 0x02000000
        }

        [Flags]
        public enum ProcessCreationFlags : uint
        {
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
        }

        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        public enum SECURITY_LOGON_TYPE
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
        public enum SE_GROUP_ATTRIBUTES : uint
        {
            SE_GROUP_MANDATORY = 0x00000001,
            SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002,
            SE_GROUP_ENABLED = 0x00000004,
            SE_GROUP_OWNER = 0x00000008,
            SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010,
            SE_GROUP_INTEGRITY = 0x00000020,
            SE_GROUP_INTEGRITY_ENABLED = 0x00000040,
            SE_GROUP_RESOURCE = 0x20000000,
            SE_GROUP_LOGON_ID = 0xC0000000
        }

        [Flags]
        public enum SE_PRIVILEGE_ATTRIBUTES : uint
        {
            SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
            SE_PRIVILEGE_ENABLED = 0x00000002,
            SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000,
        }

        public enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer,
            SidTypeLabel,
            SidTypeLogonSession
        }

        [Flags]
        public enum TokenAccessFlags : uint
        {
            TOKEN_ADJUST_DEFAULT = 0x0080,
            TOKEN_ADJUST_GROUPS = 0x0040,
            TOKEN_ADJUST_PRIVILEGES = 0x0020,
            TOKEN_ADJUST_SESSIONID = 0x0100,
            TOKEN_ASSIGN_PRIMARY = 0x0001,
            TOKEN_DUPLICATE = 0x0002,
            TOKEN_EXECUTE = 0x00020000,
            TOKEN_IMPERSONATE = 0x0004,
            TOKEN_QUERY = 0x0008,
            TOKEN_QUERY_SOURCE = 0x0010,
            TOKEN_READ = 0x00020008,
            TOKEN_WRITE = 0x000200E0,
            TOKEN_ALL_ACCESS = 0x000F01FF,
            MAXIMUM_ALLOWED = 0x02000000
        }

        public enum TOKEN_INFORMATION_CLASS
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

        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        // NTSTATUS
        public const int STATUS_SUCCESS = 0;

        // Win32 Error
        public const int ERROR_BAD_LENGTH = 0x00000018;
        public const int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;
        public const int ERROR_MORE_DATA = 0x000000EA;

        // Privilege Name
        public const string SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege";
        public const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
        public const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";
        public const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
        public const string SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege";
        public const string SE_TCB_NAME = "SeTcbPrivilege";
        public const string SE_SECURITY_NAME = "SeSecurityPrivilege";
        public const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";
        public const string SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege";
        public const string SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege";
        public const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";
        public const string SE_PROFILE_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";
        public const string SE_INCREASE_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege";
        public const string SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege";
        public const string SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege";
        public const string SE_BACKUP_NAME = "SeBackupPrivilege";
        public const string SE_RESTORE_NAME = "SeRestorePrivilege";
        public const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
        public const string SE_DEBUG_NAME = "SeDebugPrivilege";
        public const string SE_AUDIT_NAME = "SeAuditPrivilege";
        public const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege";
        public const string SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege";
        public const string SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege";
        public const string SE_UNDOCK_NAME = "SeUndockPrivilege";
        public const string SE_SYNC_AGENT_NAME = "SeSyncAgentPrivilege";
        public const string SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege";
        public const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";
        public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";
        public const string SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege";
        public const string SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege";
        public const string SE_RELABEL_NAME = "SeRelabelPrivilege";
        public const string SE_INCREASE_WORKING_SET_NAME = "SeIncreaseWorkingSetPrivilege";
        public const string SE_TIME_ZONE_NAME = "SeTimeZonePrivilege";
        public const string SE_CREATE_SYMBOLIC_LINK_NAME = "SeCreateSymbolicLinkPrivilege";
        public const string SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME = "SeDelegateSessionUserImpersonatePrivilege";

        // LSA PackageName
        public const string MSV1_0_PACKAGE_NAME = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0";
        public const string MICROSOFT_KERBEROS_NAME_A = "Kerberos";
        public const string NEGOSSP_NAME_A = "Negotiate";
    }
}
