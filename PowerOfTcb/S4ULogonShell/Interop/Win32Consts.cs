using System;

namespace S4ULogonShell.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        /*
         * NTSTATUS
         */
        public const NTSTATUS STATUS_SUCCESS = 0;
        public const NTSTATUS STATUS_TIMEOUT = 0x00000102;
        public const NTSTATUS STATUS_PROCESS_NOT_IN_JOB = 0x00000123;
        public const NTSTATUS STATUS_PROCESS_IN_JOB = 0x00000124;
        public static NTSTATUS STATUS_BUFFER_TOO_SMALL = Convert.ToInt32("0xC0000023", 16);
        public static readonly NTSTATUS STATUS_PRIVILEGE_NOT_HELD = Convert.ToInt32("0xC0000061", 16);

        /*
         * Win32 Error
         */
        public const int ERROR_SUCCESS = 0;
        public const int ERROR_MORE_DATA = 0x000000EA;

        /*
         * LSA PackageName
         */
        public const string MSV1_0_PACKAGE_NAME = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0";
        public const string MICROSOFT_KERBEROS_NAME = "Kerberos";
        public const string NEGOSSP_NAME = "Negotiate";
    }
}
