using System;
using System.Runtime.InteropServices;
using System.Text;

namespace S4uDelegator.Interop
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
            IntPtr /*ref TOKEN_PRIVILEGES*/ NewState,
            int BufferLength,
            IntPtr /*out TOKEN_PRIVILEGES*/ PreviousState,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool ConvertStringSidToSid(string StringSid, out IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            ProcessCreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            in STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            TokenAccessFlags dwDesiredAccess,
            IntPtr lpTokenAttributes,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            TOKEN_TYPE TokenType,
            out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

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

        [DllImport("advapi32.dll")]
        public static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32.dll")]
        public static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            TokenAccessFlags DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();

        /*
         * kernel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int FormatMessage(
            FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool GetComputerNameEx(
            COMPUTER_NAME_FORMAT NameType,
            StringBuilder lpBuffer,
            ref int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("kernel32.dll")]
        public static extern void SetLastError(int dwErrCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);

        /*
         * netapi32.dll
         */
        [DllImport("netapi32.dll", CharSet = CharSet.Auto)]
        public static extern int DsGetDcName(
            string ComputerName,
            string DomainName,
            IntPtr /* in Guid */ DomainGuid,
            string SiteName,
            DS_NAME_FLAGS Flags,
            out IntPtr /* DOMAIN_CONTROLLER_INFO */ DomainControllerInfo);
        
        [DllImport("netapi32.dll")]
        public static extern int NetApiBufferFree(IntPtr Buffer);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int NetGroupEnum(
            string servername,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            IntPtr /* ref IntPtr */ resume_handle);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int NetUserEnum(
            string servername,
            int level,
            USER_INFO_FILTER filter,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            IntPtr /* ref IntPtr */ resume_handle);

        /*
         * ntdll.dll
         */
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtClose(IntPtr hObject);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryInformationToken(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);

        /*
         * secur32.dll
         */
        [DllImport("secur32.dll", SetLastError = false)]
        public static extern NTSTATUS LsaConnectUntrusted(out IntPtr LsaHandle);
        
        [DllImport("secur32.dll", SetLastError = false)]
        public static extern NTSTATUS LsaFreeReturnBuffer(IntPtr buffer);

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

        [DllImport("Secur32.dll", SetLastError = true)]
        public static extern NTSTATUS LsaLookupAuthenticationPackage(
            IntPtr LsaHandle,
            in LSA_STRING PackageName,
            out uint AuthenticationPackage);

        [DllImport("secur32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool TranslateName(
            string lpAccountName,
            EXTENDED_NAME_FORMAT AccountNameFormat,
            EXTENDED_NAME_FORMAT DesiredNameFormat,
            StringBuilder lpTranslatedName,
            ref uint nSize);
    }
}
