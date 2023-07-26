using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace TokenDump.Interop
{
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        /*
         * advapi32.dll
         */
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            IntPtr /* in TOKEN_PRIVILEGES */ NewState,
            int BufferLength,
            IntPtr /* out TOKEN_PRIVILEGES */ PreviousState,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool ConvertSidToStringSid(IntPtr Sid, out string StringSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool ConvertStringSidToSid(string StringSid, out IntPtr Sid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupAccountSid(
            string strSystemName,
            IntPtr pSid,
            StringBuilder pName,
            ref int cchName,
            StringBuilder pReferencedDomainName,
            ref int cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupPrivilegeName(
            string lpSystemName,
            in LUID lpLuid,
            StringBuilder lpName,
            ref int cchName);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            ACCESS_MASK DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenThreadToken(
            IntPtr ThreadHandle,
            ACCESS_MASK DesiredAccess,
            bool OpenAsSelf,
            out IntPtr TokenHandle);

        /*
         * kernel32.dll
         */
        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            ACCESS_MASK dwDesiredAccess,
            bool bInheritHandle,
            int dwProcessId);

        /*
         * ntdll.dll
         */
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtDuplicateObject(
            IntPtr SourceProcessHandle,
            IntPtr SourceHandle,
            IntPtr TargetProcessHandle,
            out IntPtr TargetHandle,
            ACCESS_MASK DesiredAccess,
            uint HandleAttributes,
            DUPLICATE_OPTION_FLAGS Options);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryInformationProcess(
            IntPtr ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            IntPtr ProcessInformation,
            uint ProcessInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryInformationThread(
            IntPtr ThreadHandle,
            THREADINFOCLASS ThreadInformationClass,
            IntPtr ThreadInformation,
            uint ThreadInformationLength,
            out uint ReturnLength);
        
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryInformationToken(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryObject(
            IntPtr Handle,
            OBJECT_INFORMATION_CLASS ObjectInformationClass,
            IntPtr ObjectInformation,
            uint ObjectInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            uint SystemInformationLength,
            out uint ReturnLength);
    }
}
