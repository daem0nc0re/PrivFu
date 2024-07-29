using System;

namespace SwitchPriv.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const int PRIVILEGE_SET_ALL_NECESSARY = 1;

        // NtStatus
        public const NTSTATUS STATUS_SUCCESS = 0;
        public static readonly NTSTATUS STATUS_BUFFER_TOO_SMALL = Convert.ToInt32("0xC0000023", 16);
        public static readonly NTSTATUS STATUS_PRIVILEGE_NOT_HELD = Convert.ToInt32("0xC0000061", 16);

        // Win32Error
        public const int ERROR_BAD_LENGTH = 0x00000018;
        public const int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;
        public const int ERROR_PRIVILEGE_NOT_HELD = 0x00000522;
    }
}
