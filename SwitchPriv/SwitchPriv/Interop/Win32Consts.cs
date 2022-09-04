using System;

namespace SwitchPriv.Interop
{
    internal class Win32Consts
    {
        public const int PRIVILEGE_SET_ALL_NECESSARY = 1;

        // NtStatus
        public const uint STATUS_SUCCESS = 0;

        // Win32Error
        public const int ERROR_BAD_LENGTH = 0x00000018;
        public const int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;

        // Mandatory Level SID
        public const string UNTRUSTED_MANDATORY_LEVEL = "S-1-16-0";
        public const string LOW_MANDATORY_LEVEL = "S-1-16-4096";
        public const string MEDIUM_MANDATORY_LEVEL = "S-1-16-8192";
        public const string MEDIUM_PLUS_MANDATORY_LEVEL = "S-1-16-8448";
        public const string HIGH_MANDATORY_LEVEL = "S-1-16-12288";
        public const string SYSTEM_MANDATORY_LEVEL = "S-1-16-16384";
        public const string PROTECTED_MANDATORY_LEVEL = "S-1-16-20480";
        public const string SECURE_MANDATORY_LEVEL = "S-1-16-28672";

        // Privilege Constants
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
    }
}
