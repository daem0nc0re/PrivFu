using System;
using System.Runtime.InteropServices;

namespace PrivMan.Interop
{
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "LookupPrivilegeValueW", CharSet = CharSet.Unicode)]
        public static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            out LUID lpLuid);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateFile(
            out IntPtr FileHandle,
            FileAccessFlags DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            out IO_STATUS_BLOCK IoStatusBlock,
            IntPtr /* PLARGE_INTEGER */ AllocationSize,
            FILE_ATTRIBUTE_FLAGS FileAttributes,
            FILE_SHARE_ACCESS ShareAccess,
            FILE_CREATE_DISPOSITION CreateDisposition,
            FILE_CREATE_OPTIONS CreateOptions,
            IntPtr EaBuffer,
            uint EaLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtDeviceIoControlFile(
            IntPtr FileHandle,
            IntPtr Event,
            IntPtr /* PIO_APC_ROUTINE */ ApcRoutine,
            IntPtr /* PVOID */ ApcContext,
            out IO_STATUS_BLOCK IoStatusBlock,
            uint IoControlCode,
            IntPtr InputBuffer,
            uint InputBufferLength,
            IntPtr OutputBuffer,
            uint OutputBufferLength);

        [DllImport("ntdll.dll")]
        public static extern uint RtlNtStatusToDosError(NTSTATUS Status);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern void RtlSetLastWin32Error(int dwErrCode);
    }
}
