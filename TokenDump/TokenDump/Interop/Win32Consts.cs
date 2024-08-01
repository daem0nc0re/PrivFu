using System;

namespace TokenDump.Interop
{
    using HRESULT = Int32;
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        /*
         * HRESULT
         */
        public const HRESULT S_OK = 0;

        /*
         * NTSTATUS
         */
        public const NTSTATUS STATUS_SUCCESS = 0;
        public const NTSTATUS STATUS_TIMEOUT = 0x00000102;
        public const NTSTATUS STATUS_MORE_ENTRIES = 0x00000105;
        public static readonly NTSTATUS STATUS_BUFFER_OVERFLOW = Convert.ToInt32("0x80000005", 16);
        public static readonly NTSTATUS STATUS_UNSUCCESSFUL = Convert.ToInt32("0xC0000001", 16);
        public static readonly NTSTATUS STATUS_INFO_LENGTH_MISMATCH = Convert.ToInt32("0xC0000004", 16);
        public static readonly NTSTATUS STATUS_BUFFER_TOO_SMALL = Convert.ToInt32("0xC0000023", 16);
        public static readonly NTSTATUS STATUS_NO_SUCH_LOGON_SESSION = Convert.ToInt32("0xC000005F", 16);
        public static readonly NTSTATUS STATUS_PRIVILEGE_NOT_HELD = Convert.ToInt32("0xC0000061", 16);

        /*
         * Win32 Error Code
         */
        public const int ERROR_ACCESS_DENIED = 5;
        public const int ERROR_INVALID_PARAMETER = 87;
        public const int ERROR_NO_TOKEN = 1008;
    }
}
