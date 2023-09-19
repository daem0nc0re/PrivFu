using System;

namespace PrintSpoofer.Interop
{
    using NTSTATUS = Int32;
    using RPC_STATUS = Int32;

    internal class Win32Consts
    {
        /*
         * NTSTATUS
         */
        public const NTSTATUS STATUS_SUCCESS = 0;
        public const NTSTATUS STATUS_TIMEOUT = 0x00000102;
        public const NTSTATUS ERROR_IO_PENDING = 0x000003E5;
        public static readonly NTSTATUS STATUS_INFO_LENGTH_MISMATCH = Convert.ToInt32("0xC0000004", 16);
        public static readonly NTSTATUS STATUS_BUFFER_TOO_SMALL = Convert.ToInt32("0xC0000023", 16);

        /*
         * RPC_STATUS
         */
        public const RPC_STATUS RPC_S_OK = 0;

        /*
         * Privilege Name
         */
        public const string SE_DEBUG_NAME = "SeDebugPrivilege";
        public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";
        public const string SE_TCB_NAME = "SeTcbPrivilege";

        /*
         * Others
         */
        public const int SECURITY_DESCRIPTOR_REVISION = 1;
        public const int SDDL_REVISION_1 = 1;
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    }
}
