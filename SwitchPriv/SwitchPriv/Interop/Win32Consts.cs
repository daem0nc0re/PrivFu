using System;

namespace SwitchPriv.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const int PRIVILEGE_SET_ALL_NECESSARY = 1;

        // NtStatus
        public const NTSTATUS STATUS_SUCCESS = 0;
        public static readonly NTSTATUS STATUS_PRIVILEGE_NOT_HELD = Convert.ToInt32("0xC0000061", 16);

        // Win32Error
        public const int ERROR_PRIVILEGE_NOT_HELD = 0x00000522;
    }
}
