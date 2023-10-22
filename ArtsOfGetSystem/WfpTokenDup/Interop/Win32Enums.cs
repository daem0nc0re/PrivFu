using System;

namespace WfpTokenDup.Interop
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

        // For Events
        EVENT_MODIFY_STATE = 0x00000002,
        EVENT_ALL_ACCESS = 0x001F0003,

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
        GENERIC_ACCESS = 0xF0000000,
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

    internal enum ACCESS_MODE
    {
        NOT_USED_ACCESS,
        GRANT_ACCESS,
        SET_ACCESS,
        DENY_ACCESS,
        REVOKE_ACCESS,
        SET_AUDIT_SUCCESS,
        SET_AUDIT_FAILURE
    }

    internal enum ADDRESS_FAMILY : ushort
    {
        AF_UNSPEC = 0, // unspecified
        AF_UNIX = 1, // local to host (pipes, portals)
        AF_INET = 2, // internetwork: UDP, TCP, etc.
        AF_IMPLINK = 3, // arpanet imp addresses
        AF_PUP = 4, // pup protocols: e.g. BSP
        AF_CHAOS = 5, // mit CHAOS protocols
        AF_NS = 6, // XEROX NS protocols
        AF_IPX = AF_NS, // IPX protocols: IPX, SPX, etc.
        AF_ISO = 7, // ISO protocols
        AF_OSI = AF_ISO, // OSI is ISO
        AF_ECMA = 8, // european computer manufacturers
        AF_DATAKIT = 9, // datakit protocols
        AF_CCITT = 10, // CCITT protocols, X.25 etc
        AF_SNA = 11, // IBM SNA
        AF_DECnet = 12, // DECnet
        AF_DLI = 13, // Direct data link interface
        AF_LAT = 14, // LAT
        AF_HYLINK = 15, // NSC Hyperchannel
        AF_APPLETALK = 16, // AppleTalk
        AF_NETBIOS = 17, // NetBios-style addresses
        AF_VOICEVIEW = 18, // VoiceView
        AF_FIREFOX = 19, // Protocols from Firefox
        AF_UNKNOWN1 = 20, // Somebody is using this!
        AF_BAN = 21, // Banyan
        AF_ATM = 22, // Native ATM Services
        AF_INET6 = 23, // Internetwork Version 6
        AF_CLUSTER = 24, // Microsoft Wolfpack
        AF_12844 = 25, // IEEE 1284.4 WG AF
        AF_IRDA = 26, // IrDA
        AF_NETDES = 28 // Network Designers OSI & gateway
    }

    internal enum BOOLEAN : byte
    {
        FALSE = 0,
        TRUE
    }

    [Flags]
    internal enum DESKTOP_FLAGS : uint
    {
        NONE = 0x00000000,
        DF_ALLOWOTHERACCOUNTHOOK = 0x00000001
    }

    [Flags]
    internal enum DUPLICATE_OPTION_FLAGS : uint
    {
        NONE = 0x00000000,
        CLOSE_SOURCE = 0x00000001,
        SAME_ACCESS = 0x00000002,
        SAME_ATTRIBUTES = 0x00000004
    }

    internal enum EVENT_TYPE
    {
        NotificationEvent,
        SynchronizationEvent
    }

    internal enum FWP_DATA_TYPE
    {
        EMPTY = 0,
        UINT8,
        UINT16,
        UINT32,
        UINT64,
        INT8,
        INT16,
        INT32,
        INT64,
        FLOAT,
        DOUBLE,
        BYTE_ARRAY16_TYPE,
        BYTE_BLOB_TYPE,
        SID,
        SECURITY_DESCRIPTOR_TYPE,
        TOKEN_INFORMATION_TYPE,
        TOKEN_ACCESS_INFORMATION_TYPE,
        UNICODE_STRING_TYPE,
        BYTE_ARRAY6_TYPE,
        SINGLE_DATA_TYPE_MAX = 0xff,
        V4_ADDR_MASK,
        V6_ADDR_MASK,
        RANGE_TYPE,
        DATA_TYPE_MAX
    }

    internal enum FWP_IP_VERSION
    {
        V4 = 0,
        V6,
        NONE,
        MAX
    }

    internal enum FWP_MATCH_TYPE
    {
        EQUAL = 0,
        GREATER,
        LESS,
        GREATER_OR_EQUAL,
        LESS_OR_EQUAL,
        RANGE,
        FLAGS_ALL_SET,
        FLAGS_ANY_SET,
        FLAGS_NONE_SET,
        EQUAL_CASE_INSENSITIVE,
        NOT_EQUAL,
        PREFIX,
        NOT_PREFIX,
        TYPE_MAX
    }

    internal enum FWP_CLASSIFY_OPTION_TYPE
    {
        MULTICAST_STATE = 0,
        LOOSE_SOURCE_MAPPING,
        UNICAST_LIFETIME,
        MCAST_BCAST_LIFETIME,
        SECURE_SOCKET_SECURITY_FLAGS,
        SECURE_SOCKET_AUTHIP_MM_POLICY_KEY,
        SECURE_SOCKET_AUTHIP_QM_POLICY_KEY,
        LOCAL_ONLY_MAPPING,
        MAX
    }

    [Flags]
    internal enum FWPM_PROVIDER_CONTEXT_FLAGS : uint
    {
        PERSISTENT = 0x00000001,
        DOWNLEVEL = 0x00000002
    }

    internal enum FWPM_PROVIDER_CONTEXT_TYPE
    {
        IPSEC_KEYING_CONTEXT = 0,
        IPSEC_IKE_QM_TRANSPORT_CONTEXT,
        IPSEC_IKE_QM_TUNNEL_CONTEXT,
        IPSEC_AUTHIP_QM_TRANSPORT_CONTEXT,
        IPSEC_AUTHIP_QM_TUNNEL_CONTEXT,
        IPSEC_IKE_MM_CONTEXT,
        IPSEC_AUTHIP_MM_CONTEXT,
        CLASSIFY_OPTIONS_CONTEXT,
        GENERAL_CONTEXT,
        IPSEC_IKEV2_QM_TUNNEL_CONTEXT,
        IPSEC_IKEV2_MM_CONTEXT,
        IPSEC_DOSP_CONTEXT,
        IPSEC_IKEV2_QM_TRANSPORT_CONTEXT,
        NETWORK_CONNECTION_POLICY_CONTEXT,
        PROVIDER_CONTEXT_TYPE_MAX
    }

    internal enum FWPM_SESSION_FLAGS : uint
    {
        DYNAMIC = 0x00000001,
        RESERVED = 0x10000000
    }

    [Flags]
    internal enum FWPM_TUNNEL_FLAGS : uint
    {
        POINT_TO_POINT = 0x00000001,
        ENABLE_VIRTUAL_IF_TUNNELING = 0x00000002,
        RESERVED0 = 0x00000004
    }

    internal enum IKEEXT_AUTHENTICATION_IMPERSONATION_TYPE
    {
        IKEEXT_IMPERSONATION_NONE = 0,
        IKEEXT_IMPERSONATION_SOCKET_PRINCIPAL,
        IKEEXT_IMPERSONATION_MAX
    }

    internal enum IKEEXT_AUTHENTICATION_METHOD_TYPE
    {
        IPRESHARED_KEY = 0,
        ICERTIFICATE,
        IKERBEROS,
        IANONYMOUS,
        ISSL,
        INTLM_V2,
        IIPV6_CGA,
        ICERTIFICATE_ECDSA_P256,
        ICERTIFICATE_ECDSA_P384,
        ISSL_ECDSA_P256,
        ISSL_ECDSA_P384,
        IEAP,
        IRESERVED,
        IAUTHENTICATION_METHOD_TYPE_MAX
    }

    [Flags]
    internal enum IKEEXT_CERT_AUTH_FLAGS : uint
    {
        FLAG_SSL_ONE_WAY = 0x00000001,
        FLAG_DISABLE_CRL_CHECK = 0x00000002,
        ENABLE_CRL_CHECK_STRONG = 0x00000004,
        DISABLE_SSL_CERT_VALIDATION = 0x00000008,
        ALLOW_HTTP_CERT_LOOKUP = 0x00000010,
        URL_CONTAINS_BUNDLE = 0x00000020,
        DISABLE_REQUEST_PAYLOAD = 0x00000040
    }

    [Flags]
    internal enum IKEEXT_CERT_FLAGS : uint
    {
        ENABLE_ACCOUNT_MAPPING = 0x00000001,
        DISABLE_REQUEST_PAYLOAD = 0x00000002,
        USE_NAP_CERTIFICATE = 0x00000004,
        INTERMEDIATE_CA = 0x00000008,
        IGNORE_INIT_CERT_MAP_FAILURE = 0x00000010,
        PREFER_NAP_CERTIFICATE_OUTBOUND = 0x00000020,
        SELECT_NAP_CERTIFICATE = 0x00000040,
        VERIFY_NAP_CERTIFICATE = 0x00000080,
        FOLLOW_RENEWAL_CERTIFICATE = 0x00000100
    }

    internal enum IKEEXT_CERT_CONFIG_TYPE
    {
        EXPLICIT_TRUST_LIST = 0,
        ENTERPRISE_STORE,
        TRUSTED_ROOT_STORE,
        UNSPECIFIED,
        TYPE_MAX
    }

    internal enum IKEEXT_CIPHER_TYPE
    {
        DES = 0,
        TRIPLE_DES,
        AES_128,
        AES_192,
        AES_256,
        AES_GCM_128_16ICV,
        AES_GCM_256_16ICV,
        TYPE_MAX
    }

    internal enum IKEEXT_DH_GROUP
    {
        GROUP_NONE = 0,
        GROUP_1,
        GROUP_2,
        GROUP_14,
        GROUP_2048,
        ECP_256,
        ECP_384,
        GROUP_24,
        GROUP_MAX
    }

    internal enum IKEEXT_INTEGRITY_TYPE
    {
        MD5 = 0,
        SHA1,
        SHA_256,
        SHA_384,
        TYPE_MAX
    }

    [Flags]
    internal enum IKEEXT_KERB_AUTH_FLAGS : uint
    {
        DISABLE_INITIATOR_TOKEN_GENERATION = 0x00000001,
        DONT_ACCEPT_EXPLICIT_CREDENTIALS = 0x00000002
    }

    [Flags]
    internal enum IKEEXT_NTLM_V2_AUTH_FLAGS : uint
    {
        DONT_ACCEPT_EXPLICIT_CREDENTIALS = 0x00000001
    }

    [Flags]
    internal enum INHERITANCE_FLAGS : uint
    {
        NO_INHERITANCE = 0x00000000,
        SUB_OBJECTS_ONLY_INHERIT = 0x00000001,
        SUB_CONTAINERS_ONLY_INHERIT = 0x00000002,
        SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x00000003,
        INHERIT_NO_PROPAGATE = 0x00000004,
        INHERIT_ONLY = 0x00000008,
        INHERITED_ACCESS_ENTRY = 0x00000010,
        INHERITED_PARENT = 0x10000000,
        INHERITED_GRANDPARENT = 0x20000000
    }

    internal enum IPPROTO
    {
        HOPOPTS = 0,  // IPv6 Hop-by-Hop options
        ICMP = 1,
        IGMP = 2,
        GGP = 3,
        IPV4 = 4,
        ST = 5,
        TCP = 6,
        CBT = 7,
        EGP = 8,
        IGP = 9,
        PUP = 12,
        UDP = 17,
        IDP = 22,
        RDP = 27,
        IPV6 = 41, // IPv6 header
        ROUTING = 43, // IPv6 Routing header
        FRAGMENT = 44, // IPv6 fragmentation header
        ESP = 50, // encapsulating security payload
        AH = 51, // authentication header
        ICMPV6 = 58, // ICMPv6
        NONE = 59, // IPv6 no next header
        DSTOPTS = 60, // IPv6 Destination options
        ND = 77,
        ICLFXBM = 78,
        PIM = 103,
        PGM = 113,
        L2TP = 115,
        SCTP = 132,
        RAW = 255,
        MAX = 256
    }

    internal enum IPSEC_AUTH_TYPE
    {
        MD5 = 0,
        SHA_1,
        SHA_256,
        AES_128,
        AES_192,
        AES_256,
        MAX
    }

    internal enum IPSEC_AUTH_CONFIG : byte
    {
        HMAC_MD5_96 = 0,
        HMAC_SHA_1_96,
        HMAC_SHA_256_128,
        GCM_AES_128,
        GCM_AES_192,
        GCM_AES_256,
        MAX
    }

    internal enum IPSEC_CIPHER_CONFIG : byte
    {
        CBC_DES = 1,
        CBC_3DES,
        CBC_AES_128,
        CBC_AES_192,
        CBC_AES_256,
        GCM_AES_128,
        GCM_AES_192,
        GCM_AES_256,
        MAX
    }

    internal enum IPSEC_CIPHER_TYPE
    {
        DES = 1,
        TRIPLE_DES,
        AES_128,
        AES_192,
        AES_256,
        MAX
    }

    internal enum IPSEC_PFS_GROUP
    {
        PFS_NONE = 0,
        PFS_1,
        PFS_2,
        PFS_2048,
        PFS_14,
        PFS_ECP_256,
        PFS_ECP_384,
        PFS_MM,
        PFS_24,
        PFS_MAX
    }

    [Flags]
    internal enum IPSEC_POLICY_FLAGS : uint
    {
        ND_SECURE = 0x00000002,
        ND_BOUNDARY = 0x00000004,
        CLEAR_DF_ON_TUNNEL = 0x00000008,
        NAT_ENCAP_ALLOW_PEER_BEHIND_NAT = 0x00000010,
        NAT_ENCAP_ALLOW_GENERAL_NAT_TRAVERSAL = 0x00000020,
        DONT_NEGOTIATE_SECOND_LIFETIME = 0x00000040,
        DONT_NEGOTIATE_BYTE_LIFETIME = 0x00000080,
        ENABLE_V6_IN_V4_TUNNELING = 0x00000100,
        ENABLE_SERVER_ADDR_ASSIGNMENT = 0x00000200,
        TUNNEL_ALLOW_OUTBOUND_CLEAR_CONNECTION = 0x00000400,
        TUNNEL_BYPASS_ALREADY_SECURE_CONNECTION = 0x00000800,
        TUNNEL_BYPASS_ICMPV6 = 0x00001000,
        KEY_MANAGER_ALLOW_DICTATE_KEY = 0x00002000,
        KEY_MANAGER_ALLOW_NOTIFY_KEY = 0x00004000,
        RESERVED1 = 0x00008000,
        SITE_TO_SITE_TUNNEL = 0x00010000,
        BANDWIDTH1 = 0x10000000,
        BANDWIDTH2 = 0x20000000,
        BANDWIDTH3 = 0x40000000,
        BANDWIDTH4 = 0x80000000
    }

    internal enum IPSEC_TRANSFORM_TYPE
    {
        AH = 1,
        ESP_AUTH,
        ESP_CIPHER,
        ESP_AUTH_AND_CIPHER,
        ESP_AUTH_FW,
        TYPE_MAX
    }

    [Flags]
    internal enum LOGON_FLAGS : uint
    {
        LOGON_WITH_PROFILE = 0x00000001,
        LOGON_NETCREDENTIALS_ONLY = 0x00000002
    }

    internal enum MULTIPLE_TRUSTEE_OPERATION
    {
        NO_MULTIPLE_TRUSTEE,
        TRUSTEE_IS_IMPERSONATE
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

    internal enum OBJECT_INFORMATION_CLASS
    {
        ObjectBasicInformation, // q: OBJECT_BASIC_INFORMATION
        ObjectNameInformation, // q: OBJECT_NAME_INFORMATION
        ObjectTypeInformation, // q: OBJECT_TYPE_INFORMATION
        ObjectTypesInformation, // q: OBJECT_TYPES_INFORMATION
        ObjectHandleFlagInformation, // qs: OBJECT_HANDLE_FLAG_INFORMATION
        ObjectSessionInformation, // s: void // change object session // (requires SeTcbPrivilege)
        ObjectSessionObjectInformation, // s: void // change object session // (requires SeTcbPrivilege)
        MaxObjectInfoClass
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

    internal enum RPC_C_AUTHN_TYPES : uint
    {
        NONE = 0,
        DCE_PRIVATE = 1,
        DCE_PUBLIC = 2,
        DEC_PUBLIC = 4,
        GSS_NEGOTIATE = 9,
        WINNT = 10,
        GSS_SCHANNEL = 14,
        GSS_KERBEROS = 16,
        DPA = 17,
        MSN = 18,
        KERNEL = 20,
        DIGEST = 21,
        NEGO_EXTENDER = 30,
        PKU2U = 31,
        MQ = 100,
        DEFAULT = 0xFFFFFFFF
    }

    internal enum SC_STATUS_TYPE
    {
        PROCESS_INFO
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
        Removed = 0X00000004,
        UsedForAccess = 0x80000000
    }

    internal enum SEC_WINNT_AUTH_IDENTITY_FLAGS : uint
    {
        ANSI = 0x00000001,
        UNICODE
    }

    [Flags]
    internal enum SECURITY_DESCRIPTOR_CONTROL : ushort
    {
        SE_OWNER_DEFAULTED = 0x0001,
        SE_GROUP_DEFAULTED = 0x0002,
        SE_DACL_PRESENT = 0x0004,
        SE_DACL_DEFAULTED = 0x0008,
        SE_SACL_PRESENT = 0x0010,
        SE_SACL_DEFAULTED = 0x0020,
        SE_DACL_AUTO_INHERIT_REQ = 0x0100,
        SE_SACL_AUTO_INHERIT_REQ = 0x0200,
        SE_DACL_AUTO_INHERITED = 0x0400,
        SE_SACL_AUTO_INHERITED = 0x0800,
        SE_DACL_PROTECTED = 0x1000,
        SE_SACL_PROTECTED = 0x2000,
        SE_RM_CONTROL_VALID = 0x4000,
        SE_SELF_RELATIVE = 0x8000
    }

    [Flags]
    internal enum SECURITY_INFORMATION : uint
    {
        OWNER = 0x00000001,
        GROUP = 0x00000002,
        DACL = 0x00000004,
        SACL = 0x00000008,
        LABEL = 0x00000010,
        ATTRIBUTE = 0x00000020,
        SCOPE = 0x00000040,
        PROCESS_TRUST_LABEL = 0x00000080,
        BACKUP = 0x00010000,
        UNPROTECTED_SACL = 0x10000000,
        UNPROTECTED_DACL = 0x20000000,
        PROTECTED_SACL = 0x40000000,
        PROTECTED_DACL = 0x80000000
    }

    [Flags]
    internal enum SERVICE_ACCEPT : uint
    {
        NONE = 0x00000000,
        STOP = 0x00000001,
        PAUSE_CONTINUE = 0x00000002,
        SHUTDOWN = 0x00000004,
        PARAMCHANGE = 0x00000008,
        NETBINDCHANGE = 0x00000010,
        PRESHUTDOWN = 0x00000100
    }

    [Flags]
    internal enum SERVICE_FLAGS : uint
    {
        NONE = 0x00000000,
        RUNS_IN_SYSTEM_PROCESS = 0x00000001
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

    internal enum SERVICE_CONTROL_STATE
    {
        ACTIVE = 0x00000001,
        INACTIVE = 0x00000002,
        STATE_ALL = 0x00000003
    }

    internal enum SERVICE_STATE
    {
        STOPPED = 1,
        START_PENDING,
        STOP_PENDING,
        RUNNING,
        CONTINUE_PENDING,
        PAUSE_PENDING,
        PAUSED
    }

    internal enum SOCKET_GROUP : uint
    {
        NONE = 0,
        UNCONSTRAINED_GROUP = 1,
        CONSTRAINED_GROUP = 2
    }

    internal enum SOCKET_TYPE
    {
        STREAM = 1,
        DGRAM,
        RAW,
        RDM,
        SEQPACKET
    }

    internal enum SYSTEM_INFORMATION_CLASS
    {
        SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
        SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
        SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
        SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
        SystemPathInformation, // not implemented
        SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
        SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
        SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
        SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
        SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
        SystemModuleInformation, // q: RTL_PROCESS_MODULES
        SystemLocksInformation, // q: RTL_PROCESS_LOCKS
        SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
        SystemPagedPoolInformation, // not implemented
        SystemNonPagedPoolInformation, // not implemented
        SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
        SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
        SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
        SystemVdmInstemulInformation, // q: SYSTEM_VDM_INSTEMUL_INFO
        SystemVdmBopInformation, // not implemented // 20
        SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
        SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
        SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
        SystemFullMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
        SystemLoadGdiDriverInformation, // s (kernel-mode only)
        SystemUnloadGdiDriverInformation, // s (kernel-mode only)
        SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
        SystemSummaryMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
        SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
        SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
        SystemObsolete0, // not implemented
        SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
        SystemCrashDumpStateInformation, // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
        SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
        SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
        SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
        SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
        SystemPrioritySeperation, // s (requires SeTcbPrivilege)
        SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
        SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
        SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
        SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
        SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
        SystemTimeSlipNotification, // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
        SystemSessionCreate, // not implemented
        SystemSessionDetach, // not implemented
        SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
        SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
        SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
        SystemVerifierThunkExtend, // s (kernel-mode only)
        SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
        SystemLoadGdiDriverInSystemSpace, // s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
        SystemNumaProcessorMap, // q: SYSTEM_NUMA_INFORMATION
        SystemPrefetcherInformation, // q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
        SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
        SystemRecommendedSharedDataAlignment, // q: ULONG // KeGetRecommendedSharedDataAlignment
        SystemComPlusPackage, // q; s: ULONG
        SystemNumaAvailableMemory, // q: SYSTEM_NUMA_INFORMATION // 60
        SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemEmulationBasicInformation, // q: SYSTEM_BASIC_INFORMATION
        SystemEmulationProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
        SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
        SystemLostDelayedWriteInformation, // q: ULONG
        SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
        SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
        SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
        SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
        SystemObjectSecurityMode, // q: ULONG // 70
        SystemWatchdogTimerHandler, // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
        SystemWatchdogTimerInformation, // q: SYSTEM_WATCHDOG_TIMER_INFORMATION // (kernel-mode only)
        SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemWow64SharedInformationObsolete, // not implemented
        SystemRegisterFirmwareTableInformationHandler, // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
        SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
        SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
        SystemVerifierTriageInformation, // not implemented
        SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
        SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
        SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
        SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
        SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
        SystemVerifierCancellationInformation, // SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
        SystemProcessorPowerInformationEx, // not implemented
        SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
        SystemSpecialPoolInformation, // q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
        SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
        SystemErrorPortInformation, // s (requires SeTcbPrivilege)
        SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
        SystemHypervisorInformation, // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
        SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
        SystemTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
        SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
        SystemCoverageInformation, // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
        SystemPrefetchPatchInformation, // SYSTEM_PREFETCH_PATCH_INFORMATION
        SystemVerifierFaultsInformation, // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
        SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
        SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
        SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // 100
        SystemNumaProximityNodeInformation, // q; s: SYSTEM_NUMA_PROXIMITY_MAP
        SystemDynamicTimeZoneInformation, // q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
        SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
        SystemProcessorMicrocodeUpdateInformation, // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
        SystemProcessorBrandString, // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
        SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
        SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // KeQueryLogicalProcessorRelationship
        SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
        SystemStoreInformation, // q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
        SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
        SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
        SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
        SystemCpuQuotaInformation, // q; s: PS_CPU_QUOTA_QUERY_INFORMATION
        SystemNativeBasicInformation, // q: SYSTEM_BASIC_INFORMATION
        SystemErrorPortTimeouts, // SYSTEM_ERROR_PORT_TIMEOUTS
        SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
        SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
        SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
        SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
        SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
        SystemNodeDistanceInformation, // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber)
        SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
        SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
        SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
        SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
        SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
        SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
        SystemBadPageInformation,
        SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
        SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
        SystemEntropyInterruptTimingInformation, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
        SystemConsoleInformation, // q; s: SYSTEM_CONSOLE_INFORMATION
        SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
        SystemPolicyInformation, // q: SYSTEM_POLICY_INFORMATION (Warbird/Encrypt/Decrypt/Execute)
        SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
        SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
        SystemDeviceDataEnumerationInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
        SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
        SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
        SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
        SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // since WINBLUE
        SystemCriticalProcessErrorLogInformation,
        SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
        SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
        SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
        SystemEntropyInterruptTimingRawInformation,
        SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
        SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
        SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
        SystemBootMetadataInformation, // 150
        SystemSoftRebootInformation, // q: ULONG
        SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
        SystemOfflineDumpConfigInformation, // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
        SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
        SystemRegistryReconciliationInformation, // s: NULL (requires admin) (flushes registry hives)
        SystemEdidInformation, // q: SYSTEM_EDID_INFORMATION
        SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
        SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
        SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
        SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // 160
        SystemVmGenerationCountInformation,
        SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
        SystemKernelDebuggerFlags, // SYSTEM_KERNEL_DEBUGGER_FLAGS
        SystemCodeIntegrityPolicyInformation, // q; s: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
        SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
        SystemHardwareSecurityTestInterfaceResultsInformation,
        SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
        SystemAllowedCpuSetsInformation, // s: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
        SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
        SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
        SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
        SystemCodeIntegrityPolicyFullInformation,
        SystemAffinitizedInterruptProcessorInformation, // (requires SeIncreaseBasePriorityPrivilege)
        SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
        SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
        SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
        SystemWin32WerStartCallout,
        SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
        SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
        SystemInterruptSteeringInformation, // q: in: SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, out: SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT // NtQuerySystemInformationEx // 180
        SystemSupportedProcessorArchitectures, // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx
        SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
        SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
        SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
        SystemControlFlowTransition, // (Warbird/Encrypt/Decrypt/Execute)
        SystemKernelDebuggingAllowed, // s: ULONG
        SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
        SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
        SystemCodeIntegrityPoliciesFullInformation,
        SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
        SystemIntegrityQuotaInformation,
        SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
        SystemProcessorIdleMaskInformation, // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
        SystemSecureDumpEncryptionInformation,
        SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
        SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
        SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
        SystemFirmwareBootPerformanceInformation,
        SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
        SystemFirmwarePartitionInformation, // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
        SystemSpeculationControlInformation, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
        SystemDmaGuardPolicyInformation, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
        SystemEnclaveLaunchControlInformation, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
        SystemWorkloadAllowedCpuSetsInformation, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
        SystemCodeIntegrityUnlockModeInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
        SystemLeapSecondInformation, // SYSTEM_LEAP_SECOND_INFORMATION
        SystemFlags2Information, // q: SYSTEM_FLAGS_INFORMATION
        SystemSecurityModelInformation, // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
        SystemCodeIntegritySyntheticCacheInformation,
        SystemFeatureConfigurationInformation, // SYSTEM_FEATURE_CONFIGURATION_INFORMATION // since 20H1 // 210
        SystemFeatureConfigurationSectionInformation, // SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION
        SystemFeatureUsageSubscriptionInformation, // SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS
        SystemSecureSpeculationControlInformation, // SECURE_SPECULATION_CONTROL_INFORMATION
        SystemSpacesBootInformation, // since 20H2
        SystemFwRamdiskInformation, // SYSTEM_FIRMWARE_RAMDISK_INFORMATION
        SystemWheaIpmiHardwareInformation,
        SystemDifSetRuleClassInformation, // SYSTEM_DIF_VOLATILE_INFORMATION
        SystemDifClearRuleClassInformation,
        SystemDifApplyPluginVerificationOnDriver, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION
        SystemDifRemovePluginVerificationOnDriver, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION // 220
        SystemShadowStackInformation, // SYSTEM_SHADOW_STACK_INFORMATION
        SystemBuildVersionInformation, // q: in: ULONG (LayerNumber), out: SYSTEM_BUILD_VERSION_INFORMATION // NtQuerySystemInformationEx // 222
        SystemPoolLimitInformation, // SYSTEM_POOL_LIMIT_INFORMATION (requires SeIncreaseQuotaPrivilege)
        SystemCodeIntegrityAddDynamicStore,
        SystemCodeIntegrityClearDynamicStores,
        SystemDifPoolTrackingInformation,
        SystemPoolZeroingInformation, // q: SYSTEM_POOL_ZEROING_INFORMATION
        SystemDpcWatchdogInformation, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION
        SystemDpcWatchdogInformation2, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2
        SystemSupportedProcessorArchitectures2, // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx // 230
        SystemSingleProcessorRelationshipInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor)
        SystemXfgCheckFailureInformation, // q: SYSTEM_XFG_FAILURE_INFORMATION
        SystemIommuStateInformation, // SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
        SystemHypervisorMinrootInformation, // SYSTEM_HYPERVISOR_MINROOT_INFORMATION
        SystemHypervisorBootPagesInformation, // SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
        SystemPointerAuthInformation, // SYSTEM_POINTER_AUTH_INFORMATION
        SystemSecureKernelDebuggerInformation,
        SystemOriginalImageFeatureInformation, // q: in: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT, out: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT // NtQuerySystemInformationEx
        MaxSystemInfoClass
    }

    internal enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1, // q: TOKEN_USER, SE_TOKEN_USER
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

    internal enum TRUSTEE_FORM
    {
        SID,
        NAME,
        TRUSTEE_BAD_FORM,
        OBJECTS_AND_SID,
        OBJECTS_AND_NAME
    }

    internal enum TRUSTEE_TYPE
    {
        UNKNOWN,
        USER,
        GROUP,
        DOMAIN,
        ALIAS,
        WELL_KNOWN_GROUP,
        DELETED,
        INVALID,
        COMPUTER
    }

    internal enum WFPALE_IOCTL_CODES : uint
    {
        QueryTokenById = 0x124008,
        ProcessEndpointPropertiesQuery = 0x124018,
        ProcessEndpointEnumIoctl = 0x12401E,
        SetOption = 0x124020,
        ProcessTokenReference = 0x128000,
        ReleaseTokenInformationById = 0x128004,
        ProcessExplicitCredentialQuery = 0x128010
    }

    [Flags]
    internal enum WSA_FLAGS : uint
    {
        OVERLAPPED = 0x00000001,
        MULTIPOINT_C_ROOT = 0x00000002,
        MULTIPOINT_C_LEAF = 0x00000004,
        MULTIPOINT_D_ROOT = 0x00000008,
        MULTIPOINT_D_LEAF = 0x00000010,
        ACCESS_SYSTEM_SECURITY = 0x00000040,
        NO_HANDLE_INHERIT = 0x00000080,
        REGISTERED_IO = 0x00000100
    }

    [Flags]
    internal enum WSA_PROVIDOR_FLAGS : uint
    {
        MULTIPLE_PROTO_ENTRIES = 0x00000001,
        RECOMMENDED_PROTO_ENTRY = 0x00000002,
        HIDDEN = 0x00000004,
        MATCHES_PROTOCOL_ZERO = 0x00000008,
        NETWORKDIRECT_PROVIDER = 0x00000010
    }

    [Flags]
    internal enum WSA_SERVICE_FLAGS1 : uint
    {
        CONNECTIONLESS = 0x00000001,
        GUARANTEED_DELIVERY = 0x00000002,
        GUARANTEED_ORDER = 0x00000004,
        MESSAGE_ORIENTED = 0x00000008,
        PSEUDO_STREAM = 0x00000010,
        GRACEFUL_CLOSE = 0x00000020,
        EXPEDITED_DATA = 0x00000040,
        CONNECT_DATA = 0x00000080,
        DISCONNECT_DATA = 0x00000100,
        SUPPORT_BROADCAST = 0x00000200,
        SUPPORT_MULTIPOINT = 0x00000400,
        MULTIPOINT_CONTROL_PLANE = 0x00000800,
        MULTIPOINT_DATA_PLANE = 0x00001000,
        QOS_SUPPORTED = 0x00002000,
        INTERRUPT = 0x00004000,
        UNI_SEND = 0x00008000,
        UNI_RECV = 0x00010000,
        IFS_HANDLES = 0x00020000,
        PARTIAL_MESSAGE = 0x00040000,
        SAN_SUPPORT_SDP = 0x00080000
    }

    internal enum WTS_INFO_CLASS
    {
        WTSInitialProgram,
        WTSApplicationName,
        WTSWorkingDirectory,
        WTSOEMId,
        WTSSessionId,
        WTSUserName,
        WTSWinStationName,
        WTSDomainName,
        WTSConnectState,
        WTSClientBuildNumber,
        WTSClientName,
        WTSClientDirectory,
        WTSClientProductId,
        WTSClientHardwareId,
        WTSClientAddress,
        WTSClientDisplay,
        WTSClientProtocolType,
        WTSIdleTime,
        WTSLogonTime,
        WTSIncomingBytes,
        WTSOutgoingBytes,
        WTSIncomingFrames,
        WTSOutgoingFrames,
        WTSClientInfo,
        WTSSessionInfo,
        WTSSessionInfoEx,
        WTSConfigInfo,
        WTSValidationInfo,
        WTSSessionAddressV4,
        WTSIsRemoteSession
    }
}
