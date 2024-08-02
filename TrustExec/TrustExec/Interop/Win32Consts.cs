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
