using System;

namespace TokenAssignor.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const NTSTATUS STATUS_SUCCESS = 0;
        public static readonly NTSTATUS STATUS_NO_MORE_ENTRIES = Convert.ToInt32("0x8000001A", 16);
        public static readonly NTSTATUS STATUS_THREAD_IS_TERMINATING = Convert.ToInt32("0xC000004B", 16);
        public static readonly NTSTATUS STATUS_PRIVILEGE_NOT_HELD = Convert.ToInt32("0xC0000061", 16);
        public const int ERROR_INSUFFICIENT_BUFFER = 0x7A;
        public const int ERROR_PRIVILEGE_NOT_HELD = 0x522;
    }
}
