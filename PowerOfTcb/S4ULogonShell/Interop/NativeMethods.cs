using System;
using System.Runtime.InteropServices;
using System.Text;

namespace S4ULogonShell.Interop
{
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            IntPtr /* LPSECURITY_ATTRIBUTES */ lpProcessAttributes,
            IntPtr /* LPSECURITY_ATTRIBUTES */ lpThreadAttributes,
            bool bInheritHandles,
            PROCESS_CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            in STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(
            IntPtr hToken,
            LOGON_FLAGS dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            PROCESS_CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            in STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool GetComputerNameEx(
            COMPUTER_NAME_FORMAT NameType,
            StringBuilder lpBuffer,
            ref int nSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupAccountName(
            string lpSystemName,
            string lpAccountName,
            IntPtr Sid,
            ref int cbSid,
            StringBuilder ReferencedDomainName,
            ref int cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LookupAccountSid(
            string lpSystemName,
            IntPtr Sid,
            StringBuilder Name,
            ref int cchName,
            StringBuilder ReferencedDomainName,
            ref int cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("secur32.dll")]
        public static extern NTSTATUS LsaDeregisterLogonProcess(IntPtr LsaHandle);

        [DllImport("secur32.dll")]
        public static extern NTSTATUS LsaLogonUser(
            IntPtr LsaHandle,
            in LSA_STRING OriginName,
            SECURITY_LOGON_TYPE LogonType,
            uint AuthenticationPackage,
            IntPtr AuthenticationInformation,
            uint AuthenticationInformationLength,
            IntPtr /* in TOKEN_GROUPS */ LocalGroups,
            in TOKEN_SOURCE SourceContext,
            out IntPtr ProfileBuffer,
            out uint ProfileBufferLength,
            out LUID LogonId,
            IntPtr Token, // [out] PHANDLE
            out QUOTA_LIMITS Quotas,
            out NTSTATUS SubStatus);

        [DllImport("secur32.dll")]
        public static extern NTSTATUS LsaLookupAuthenticationPackage(
            IntPtr LsaHandle,
            in LSA_STRING PackageName,
            out uint AuthenticationPackage);

        [DllImport("advapi32.dll")]
        public static extern int LsaNtStatusToWinError(NTSTATUS Status);

        [DllImport("secur32.dll")]
        public static extern NTSTATUS LsaRegisterLogonProcess(
            in LSA_STRING LogonProcessName, // Arbitrary string such as "User32LogonProcess"
            out IntPtr LsaHandle,
            out uint /* LSA_OPERATIONAL_MODE */ SecurityMode); // Reserved parameter

        [DllImport("netapi32.dll")]
        public static extern int NetApiBufferFree(IntPtr Buffer);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int NetUserEnum(
            string servername,
            int level,
            USER_INFO_FILTER filter,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            IntPtr resume_handle);

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
        public static extern NTSTATUS NtDuplicateToken(
            IntPtr ExistingTokenHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            BOOLEAN EffectiveOnly,
            TOKEN_TYPE TokenType,
            out IntPtr NewTokenHandle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenProcess(
            out IntPtr ProcessHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            in CLIENT_ID ClientId);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenProcessToken(
            IntPtr ProcessHandle,
            ACCESS_MASK DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryInformationToken(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtResumeThread(
            IntPtr ThreadHandle,
            out uint SuspendCount);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtSetInformationThread(
            IntPtr ThreadHandle,
            THREADINFOCLASS ThreadInformationClass,
            IntPtr ThreadInformation,
            uint ThreadInformationLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtSetInformationToken(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWaitForSingleObject(
            IntPtr Handle,
            bool Alertable,
            IntPtr /* in LARGE_INTEGER */ Timeout);

        [DllImport("ntdll.dll")]
        public static extern uint RtlNtStatusToDosError(NTSTATUS Status);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern void RtlSetLastWin32Error(int dwErrCode);

        [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool WTSEnumerateSessionsW(
            IntPtr hServer,
            int Reserved,
            int Version, // Must be 1
            out IntPtr /* PWTS_SESSION_INFOW* */ ppSessionInfo,
            out int pCount);

        [DllImport("wtsapi32.dll")]
        public static extern void WTSFreeMemory(IntPtr pMemory);
    }
}
