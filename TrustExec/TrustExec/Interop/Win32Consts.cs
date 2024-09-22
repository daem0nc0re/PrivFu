using System;

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
        public const int ERROR_SUCCESS = 0;
        public const int ERROR_BAD_LENGTH = 0x00000018;
        public const int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;
        public const int ERROR_MORE_DATA = 0x000000EA;

        // LSA Package Names
        public const string MSV1_0_PACKAGE_NAME = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0";
        public const string MICROSOFT_KERBEROS_NAME = "Kerberos";
        public const string NEGOSSP_NAME = "Negotiate";
    }
}
