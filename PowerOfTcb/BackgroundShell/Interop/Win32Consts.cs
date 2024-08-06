using System;

namespace BackgroundShell.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const NTSTATUS STATUS_SUCCESS = 0;
        public static readonly NTSTATUS STATUS_PRIVILEGE_NOT_HELD = Convert.ToInt32("0xC0000061", 16);
        public const int ERROR_PRIVILEGE_NOT_HELD = 0x522;
    }
}
