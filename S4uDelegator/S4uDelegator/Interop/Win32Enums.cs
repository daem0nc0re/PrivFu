using System;

namespace S4uDelegator.Interop
{
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

    internal enum DC_ADDRESS_TYPE : uint
    {
        INET_ADDRESS = 1,
        NETBIOS_ADDRESS
    }

    [Flags]
    internal enum DS_FLAGS : uint
    {
        PDC_FLAG = 0x00000001, // DC is PDC of Domain
        GC_FLAG = 0x00000004, // DC is a GC of forest
        LDAP_FLAG = 0x00000008, // Server supports an LDAP server
        DS_FLAG = 0x00000010, // DC supports a DS and is a Domain Controller
        KDC_FLAG = 0x00000020, // DC is running KDC service
        TIMESERV_FLAG = 0x00000040, // DC is running time service
        CLOSEST_FLAG = 0x00000080, // DC is in closest site to client
        WRITABLE_FLAG = 0x00000100, // DC has a writable DS
        GOOD_TIMESERV_FLAG = 0x00000200, // DC is running time service (and has clock hardware)
        NDNC_FLAG = 0x00000400,    // DomainName is non-domain NC serviced by the LDAP server
        SELECT_SECRET_DOMAIN_6_FLAG = 0x00000800, // DC has some secrets
        FULL_SECRET_DOMAIN_6_FLAG = 0x00001000, // DC has all secrets
        WS_FLAG = 0x00002000, // DC is running web service
        DS_8_FLAG = 0x00004000, // DC is running Win8 or later
        DS_9_FLAG = 0x00008000, // DC is running Win8.1 or later
        DS_10_FLAG = 0x00010000, // DC is running WinThreshold or later
        KEY_LIST_FLAG = 0x00020000, // DC supports key list requests
        PING_FLAGS = 0x000FFFFF // Flags returned on ping
    }

    [Flags]
    internal enum DS_NAME_FLAGS : uint
    {
        NONE = 0x00000000,
        FORCE_REDISCOVERY = 0x00000001,
        DIRECTORY_SERVICE_REQUIRED = 0x00000010,
        DIRECTORY_SERVICE_PREFERRED = 0x00000020,
        GC_SERVER_REQUIRED = 0x00000040,
        PDC_REQUIRED = 0x00000080,
        BACKGROUND_ONLY = 0x00000100,
        IP_REQUIRED = 0x00000200,
        KDC_REQUIRED = 0x00000400,
        TIMESERV_REQUIRED = 0x00000800,
        WRITABLE_REQUIRED = 0x00001000,
        GOOD_TIMESERV_PREFERRED = 0x00002000,
        AVOID_SELF = 0x00004000,
        ONLY_LDAP_NEEDED = 0x00008000,
        IS_FLAT_NAME = 0x00010000,
        IS_DNS_NAME = 0x00020000,
        TRY_NEXTCLOSEST_SITE = 0x00040000,
        DIRECTORY_SERVICE_6_REQUIRED = 0x00080000,
        WEB_SERVICE_REQUIRED = 0x00100000,
        DIRECTORY_SERVICE_8_REQUIRED = 0x00200000,
        DIRECTORY_SERVICE_9_REQUIRED = 0x00400000,
        DIRECTORY_SERVICE_10_REQUIRED = 0x00800000,
        KEY_LIST_SUPPORT_REQUIRED = 0x01000000,
        RETURN_DNS_NAME = 0x40000000,
        RETURN_FLAT_NAME = 0x80000000,
        VALID_FLAGS = 0xC1FFFFF1,
        DIRECTORY_SERVICE_ALL_VERSIONS = 0x00E80010
    }

    internal enum EXTENDED_NAME_FORMAT
    {
        NameUnknown = 0,
        NameFullyQualifiedDN = 1, // CN=Jeff Smith,OU=Users,DC=Engineering,DC=Microsoft,DC=Com
        NameSamCompatible = 2, // Engineering\JSmith
        NameDisplay = 3, // Jeff Smith
        NameUniqueId = 6, // {4fa050f0-f561-11cf-bdd9-00aa003a77b6}
        NameCanonical = 7, // engineering.microsoft.com/software/someone
        NameUserPrincipal = 8, // someone@example.com
        NameCanonicalEx = 9, // engineering.microsoft.com/software\nJSmith
        NameServicePrincipal = 10, // www/www.microsoft.com@microsoft.com
        NameDnsDomain = 12,
        NameGivenName = 13,
        NameSurname = 14
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
        SYNCHRONIZE = 0x00100000,
        MAXIMUM_ALLOWED = 0x02000000
    }

    [Flags]
    internal enum ProcessCreationFlags : uint
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
        USED_FOR_ACCESS = 0x80000000,
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
