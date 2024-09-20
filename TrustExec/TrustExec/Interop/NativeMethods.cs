using System;
using System.Runtime.InteropServices;
using System.Text;

namespace TrustExec.Interop
{
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        /*
         * advapi32.dll
         */
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

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupAccountName(
            string lpSystemName,
            string lpAccountName,
            IntPtr Sid,
            ref int cbSid,
            StringBuilder ReferencedDomainName,
            ref int cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupAccountSid(
            string strSystemName,
            IntPtr pSid,
            StringBuilder pName,
            ref int cchName,
            StringBuilder pReferencedDomainName,
            ref int cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("advapi32.dll")]
        public static extern NTSTATUS LsaFreeMemory(IntPtr Buffer);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern NTSTATUS LsaManageSidNameMapping(
            LSA_SID_NAME_MAPPING_OPERATION_TYPE OperationType,
            IntPtr OperationInput,
            out IntPtr OperationOutput);

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
        public static extern NTSTATUS NtCreateToken(
            out IntPtr TokenHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            TOKEN_TYPE TokenType,
            in LUID AuthenticationId,
            in LARGE_INTEGER ExpirationTime,
            in TOKEN_USER TokenUser,
            IntPtr /* in TOKEN_GROUPS */ TokenGroups,
            IntPtr /* in TOKEN_PRIVILEGES */ TokenPrivileges,
            in TOKEN_OWNER TokenOwner,
            in TOKEN_PRIMARY_GROUP TokenPrimaryGroup,
            in TOKEN_DEFAULT_DACL TokenDefaultDacl,
            in TOKEN_SOURCE TokenSource);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtDuplicateToken(
            IntPtr ExistingTokenHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            BOOLEAN EffectiveOnly,
            TOKEN_TYPE TokenType,
            out IntPtr NewTokenHandle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryInformationToken(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);

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

        /*
         * sspicli.dll
         */
        [DllImport("sspicli.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUserExExW(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            LOGON_TYPE dwLogonType,
            LOGON_PROVIDER dwLogonProvider,
            IntPtr /* PTOKEN_GROUPS */ pTokenGroups,
            out IntPtr phToken,
            out IntPtr /* PSID* */ ppLogonSid,
            out IntPtr /* PVOID* */ ppProfileBuffer,
            out int pdwProfileLength,
            out QUOTA_LIMITS pQuotaLimits);

        /*
         * wtsapi32.dll
         */
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
