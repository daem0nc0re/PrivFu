using System;

namespace UserRightsUtil.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        // Status Codes
        public const NTSTATUS STATUS_SUCCESS = 0;
        public const int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;
        public const int NERR_Success = 0;

        // Flags for netapi32.dll API
        public const int LG_INCLUDE_INDIRECT = 0x0001;
        public const int MAX_PREFERRED_LENGTH = -1;
    }
}
