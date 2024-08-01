using System;
using System.Runtime.InteropServices;
using System.Text;

namespace TokenDump.Interop
{
    using HRESULT = Int32;
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        /*
         * advapi32.dll
         */
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
         * kernelbase.dll
         */
        [DllImport("kernelbase.dll", CharSet = CharSet.Unicode)]
        public static extern HRESULT AppContainerLookupMoniker(
            IntPtr /* PSID */ Sid,
            out IntPtr /* LPWSTR* */ Moniker);

        [DllImport("kernelbase.dll", SetLastError = true)]
        public static extern bool AppContainerFreeMemory(IntPtr Memory);

        [DllImport("kernelbase.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool DeriveCapabilitySidsFromName(
            string CapName,
            out IntPtr /* PSID** */ CapabilityGroupSids,
            out int CapabilityGroupSidCount,
            out IntPtr /* PSID** */ CapabilitySids,
            out int CapabilitySidCount);

        /*
         * ntdll.dll
         */
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtAdjustPrivilegesToken(
            IntPtr TokenHandle,
            BOOLEAN DisableAllPrivileges,
            IntPtr /* PTOKEN_PRIVILEGES */ NewState,
            uint BufferLength,
            IntPtr /* out PTOKEN_PRIVILEGES */ PreviousState, // Optional
            out uint ReturnLength);

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
        public static extern NTSTATUS NtEnumerateKey(
            IntPtr KeyHandle,
            uint Index,
            KEY_INFORMATION_CLASS KeyInformationClass,
            IntPtr KeyInformation,
            uint Length,
            out uint ResultLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenDirectoryObject(
            out IntPtr DirectoryHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenKey(
            out IntPtr KeyHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenSymbolicLinkObject(
            out IntPtr LinkHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryDirectoryObject(
            IntPtr DirectoryHandle,
            IntPtr Buffer,
            uint Length,
            BOOLEAN ReturnSingleEntry,
            BOOLEAN RestartScan,
            ref uint Context,
            out uint ReturnLength);

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
        public static extern NTSTATUS NtQueryKey(
            IntPtr KeyHandle,
            KEY_INFORMATION_CLASS KeyInformationClass,
            IntPtr KeyInformation,
            uint Length,
            out uint ResultLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryObject(
            IntPtr Handle,
            OBJECT_INFORMATION_CLASS ObjectInformationClass,
            IntPtr ObjectInformation,
            uint ObjectInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQuerySymbolicLinkObject(
            IntPtr LinkHandle,
            ref UNICODE_STRING LinkTarget,
            out uint ReturnedLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            uint SystemInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern uint RtlNtStatusToDosError(NTSTATUS Status);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern void RtlSetLastWin32Error(int dwErrCode);

        /*
         * secur32.dll
         */
        [DllImport("secur32.dll")]
        public static extern NTSTATUS LsaGetLogonSessionData(
            in LUID LogonId, // in LUID
            out IntPtr /* PSECURITY_LOGON_SESSION_DATA* */ ppLogonSessionData);

        [DllImport("secur32.dll")]
        public static extern NTSTATUS LsaFreeReturnBuffer(IntPtr Buffer);
    }
}
