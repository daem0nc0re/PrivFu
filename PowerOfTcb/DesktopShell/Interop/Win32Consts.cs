using System;

namespace DesktopShell.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const NTSTATUS STATUS_SUCCESS = 0;
        public static readonly NTSTATUS STATUS_PRIVILEGE_NOT_HELD = Convert.ToInt32("0xC0000061", 16);
        public static readonly LUID SE_ASSIGNPRIMARYTOKEN_PRIVILEGE = new LUID { QuadPart = 3L };
        public static readonly LUID SE_TCB_PRIVILEGE = new LUID { QuadPart = 7L };
    }
}
