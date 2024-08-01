using System;
using System.Net.NetworkInformation;

namespace TrustExec.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        // NTSTATUS
        public const NTSTATUS STATUS_SUCCESS = 0;
        public static readonly NTSTATUS STATUS_INVALID_PARAMETER = Convert.ToInt32("0xC000000D", 16);
        public static readonly NTSTATUS STATUS_NOT_FOUND = Convert.ToInt32("0xC0000225", 16);
        public static readonly NTSTATUS STATUS_BUFFER_TOO_SMALL = Convert.ToInt32("0xC0000023", 16);
        public static readonly NTSTATUS STATUS_PRIVILEGE_NOT_HELD = Convert.ToInt32("0xC0000061", 16);

        // Win32Error
        public const int ERROR_BAD_LENGTH = 0x00000018;
        public const int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;

        // Well known LUID
        public static readonly LUID ANONYMOUS_LOGON_LUID = LUID.FromInt64(0x3e6);
        public static readonly LUID SYSTEM_LUID = LUID.FromInt64(0x3e7);

        // Well known RID
        public const string SECURITY_WORLD_RID = "S-1-1-0";
        public const string SECURITY_AUTHENTICATED_USER_RID = "S-1-5-11";
        public const string DOMAIN_ALIAS_RID_ADMINS = "S-1-5-32-544";
        public const string DOMAIN_ALIAS_RID_USERS = "S-1-5-32-545";
        public const string LOCAL_SYSTEM_RID = "S-1-5-18";
        public const string TRUSTED_INSTALLER_RID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        public const string UNTRUSTED_MANDATORY_LEVEL = "S-1-16-0";
        public const string LOW_MANDATORY_LEVEL = "S-1-16-4096";
        public const string MEDIUM_MANDATORY_LEVEL = "S-1-16-8192";
        public const string MEDIUM_PLUS_MANDATORY_LEVEL = "S-1-16-8448";
        public const string HIGH_MANDATORY_LEVEL = "S-1-16-12288";
        public const string SYSTEM_MANDATORY_LEVEL = "S-1-16-16384";
        public const string PROTECTED_MANDATORY_LEVEL = "S-1-16-20480";
        public const string SECURE_MANDATORY_LEVEL = "S-1-16-28672";

        // LogonType
        public const int LOGON32_LOGON_INTERACTIVE = 2;
        public const int LOGON32_LOGON_NETWORK = 3;
        public const int LOGON32_LOGON_BATCH = 4;
        public const int LOGON32_LOGON_SERVICE = 5;
        public const int LOGON32_LOGON_UNLOCK = 7;
        public const int LOGON32_LOGON_NETWORK_CLEARTEXT = 8;
        public const int LOGON32_LOGON_NEW_CREDENTIALS = 9;

        // LogonProvider
        public const int LOGON32_PROVIDER_DEFAULT = 0;
        public const int LOGON32_PROVIDER_WINNT35 = 1;
        public const int LOGON32_PROVIDER_WINNT40 = 2;
        public const int LOGON32_PROVIDER_WINNT50 = 3;
        public const int LOGON32_PROVIDER_VIRTUAL = 4;

        // ContextTrackingMode for SECURITY_QUALITY_OF_SERVICE
        public const byte SECURITY_STATIC_TRACKING = 0;
        public const byte SECURITY_DYNAMIC_TRACKING = 1;

        // Well known SID_IDENTIFIER_AUTHORITY
        public static readonly SID_IDENTIFIER_AUTHORITY SECURITY_NULL_SID_AUTHORITY = new SID_IDENTIFIER_AUTHORITY { Value = new byte[6] { 0, 0, 0, 0, 0, 0 } };
        public static readonly SID_IDENTIFIER_AUTHORITY SECURITY_WORLD_SID_AUTHORITY = new SID_IDENTIFIER_AUTHORITY { Value = new byte[6] { 0, 0, 0, 0, 0, 1 } };
        public static readonly SID_IDENTIFIER_AUTHORITY SECURITY_LOCAL_SID_AUTHORITY = new SID_IDENTIFIER_AUTHORITY { Value = new byte[6] { 0, 0, 0, 0, 0, 2 } };
        public static readonly SID_IDENTIFIER_AUTHORITY SECURITY_CREATOR_SID_AUTHORITY = new SID_IDENTIFIER_AUTHORITY { Value = new byte[6] { 0, 0, 0, 0, 0, 3 } };
        public static readonly SID_IDENTIFIER_AUTHORITY SECURITY_NON_UNIQUE_AUTHORITY = new SID_IDENTIFIER_AUTHORITY { Value = new byte[6] { 0, 0, 0, 0, 0, 4 } };
        public static readonly SID_IDENTIFIER_AUTHORITY SECURITY_NT_AUTHORITY = new SID_IDENTIFIER_AUTHORITY { Value = new byte[6] { 0, 0, 0, 0, 0, 5 } };
        public static readonly SID_IDENTIFIER_AUTHORITY SECURITY_RESOURCE_MANAGER_AUTHORITY = new SID_IDENTIFIER_AUTHORITY { Value = new byte[6] { 0, 0, 0, 0, 0, 9 } };
    }
}
