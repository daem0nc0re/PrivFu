using System;
using System.Runtime.InteropServices;
using System.Text;

namespace TrustExec.Interop
{
    class Win32Api
    {
        /*
         * advapi32.dll
         */
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            IntPtr NewState, // ref TOKEN_PRIVILEGES
            int BufferLength,
            IntPtr PreviousState, // out TOKEN_PRIVILEGES
            IntPtr ReturnLength); // out int

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AllocateAndInitializeSid(
            ref Win32Struct.SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
            byte nSubAuthorityCount,
            int dwSubAuthority0,
            int dwSubAuthority1,
            int dwSubAuthority2,
            int dwSubAuthority3,
            int dwSubAuthority4,
            int dwSubAuthority5,
            int dwSubAuthority6,
            int dwSubAuthority7,
            out IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool AllocateLocallyUniqueId(out Win32Struct.LUID Luid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertStringSidToSid(string StringSid, out IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            Win32Const.ProcessCreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref Win32Struct.STARTUPINFO lpStartupInfo,
            out Win32Struct.PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public extern static bool CreateProcessWithToken(
            IntPtr hToken,
            Win32Const.LogonFlags dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            Win32Const.ProcessCreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref Win32Struct.STARTUPINFO lpStartupInfo,
            out Win32Struct.PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            Win32Const.TokenAccessFlags dwDesiredAccess,
            IntPtr lpTokenAttributes,
            Win32Const.SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            Win32Const.TOKEN_TYPE TokenType,
            out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            Win32Const.TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool IsValidSid(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupAccountName(
            string lpSystemName,
            string lpAccountName,
            IntPtr Sid,
            ref int cbSid,
            StringBuilder ReferencedDomainName,
            ref int cchReferencedDomainName,
            out Win32Const.SID_NAME_USE peUse);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupAccountSid(
            string strSystemName,
            IntPtr pSid,
            StringBuilder pName,
            ref int cchName,
            StringBuilder pReferencedDomainName,
            ref int cchReferencedDomainName,
            out Win32Const.SID_NAME_USE peUse);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupPrivilegeName(
            string lpSystemName,
            ref Win32Struct.LUID lpLuid,
            StringBuilder lpName,
            ref int cchName);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            out Win32Struct.LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            Win32Const.TokenAccessFlags DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetThreadToken(
            IntPtr Thread,
            IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetTokenInformation(
            IntPtr TokenHandle,
            Win32Const.TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength);

        [DllImport("advapi32.dll")]
        public static extern uint LsaFreeMemory(IntPtr Buffer);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern uint LsaManageSidNameMapping(
            Win32Const.LSA_SID_NAME_MAPPING_OPERATION_TYPE OperationType,
            Win32Struct.LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT OperationInput,
            out IntPtr OperationOutput);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern uint LsaManageSidNameMapping(
            Win32Const.LSA_SID_NAME_MAPPING_OPERATION_TYPE OperationType,
            Win32Struct.LSA_SID_NAME_MAPPING_OPERATION_REMOVE_INPUT OperationInput,
            out IntPtr OperationOutput);

        /*
         * kenel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hModule);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            Win32Const.ProcessCreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref Win32Struct.STARTUPINFO lpStartupInfo,
            out Win32Struct.PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint FormatMessage(
            Win32Const.FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FreeLibrary(IntPtr hLibModule);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int GetCurrentThreadId();

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            Win32Const.ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);

        /*
         * ntdll.dll
         */
        [DllImport("ntdll.dll")]
        public static extern void RtlGetNtVersionNumbers(
            ref int MajorVersion,
            ref int MinorVersion,
            ref int BuildNumber);

        [DllImport("ntdll.dll")]
        public static extern uint ZwCreateToken(
            out IntPtr TokenHandle,
            Win32Const.TokenAccessFlags DesiredAccess,
            ref Win32Struct.OBJECT_ATTRIBUTES ObjectAttributes,
            Win32Const.TOKEN_TYPE TokenType,
            ref Win32Struct.LUID AuthenticationId,
            ref Win32Struct.LARGE_INTEGER ExpirationTime,
            ref Win32Struct.TOKEN_USER TokenUser,
            ref Win32Struct.TOKEN_GROUPS TokenGroups,
            ref Win32Struct.TOKEN_PRIVILEGES TokenPrivileges,
            ref Win32Struct.TOKEN_OWNER TokenOwner,
            ref Win32Struct.TOKEN_PRIMARY_GROUP TokenPrimaryGroup,
            ref Win32Struct.TOKEN_DEFAULT_DACL TokenDefaultDacl,
            ref Win32Struct.TOKEN_SOURCE TokenSource);

        [DllImport("ntdll.dll")]
        public static extern uint ZwSetInformationProcess(
            IntPtr ProcessHandle,
            Win32Const.PROCESS_INFORMATION_CLASS ProcessInformationClass,
            IntPtr ProcessInformation,
            int ProcessInformationLength);

        /*
         * sspicli.dll
         */
        [DllImport("sspicli.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUserExExW(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            IntPtr pTokenGroups,
            out IntPtr phToken,
            IntPtr ppLogonSid,
            IntPtr ppProfileBuffer,
            IntPtr pdwProfileLength,
            IntPtr pQuotaLimits);
    }
}
