using System;

namespace SwitchPriv.Interop
{
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
    internal enum PrivilegeAttributeFlags : uint
    {
        SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
        SE_PRIVILEGE_ENABLED = 0x00000002,
        SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000
    }

    [Flags]
    internal enum ProcessAccessFlags : uint
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
        SYNCHRONIZE = 0x00100000
    }

    internal enum PROCESS_INFORMATION_CLASS
    {
        ProcessBasicInformation = 0x00,
        ProcessDebugPort = 0x07,
        ProcessExceptionPort = 0x08,
        ProcessAccessToken = 0x09,
        ProcessWow64Information = 0x1A,
        ProcessImageFileName = 0x1B,
        ProcessDebugObjectHandle = 0x1E,
        ProcessDebugFlags = 0x1F,
        ProcessExecuteFlags = 0x22,
        ProcessInstrumentationCallback = 0x28,
        MaxProcessInfoClass = 0x64
    }

    internal enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    [Flags]
    internal enum SE_GROUP_ATTRIBUTES : uint
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
    internal enum SE_PRIVILEGE_ATTRIBUTES : uint
    {
        SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
        SE_PRIVILEGE_ENABLED = 0x00000002,
        SE_PRIVILEGE_REMOVED = 0x00000004,
        SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000,
    }

    [Flags]
    internal enum TokenAccessFlags : uint
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

    internal enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }
}
