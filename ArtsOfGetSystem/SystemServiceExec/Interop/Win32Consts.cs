using System;

namespace SystemServiceExec.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        internal const NTSTATUS STATUS_SUCCESS = 0;
        internal const NTSTATUS STATUS_NOT_ALL_ASSIGNED = 0x00000106;
        internal const NTSTATUS STATUS_BUFFER_TOO_SMALL = unchecked((NTSTATUS)0xC0000023);
        internal const NTSTATUS STATUS_NO_SUCH_PRIVILEGE = unchecked((NTSTATUS)0xC0000060);
        internal const NTSTATUS STATUS_PRIVILEGE_NOT_HELD = unchecked((NTSTATUS)0xC0000061);
    }
}
