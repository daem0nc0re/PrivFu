using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace WfpTokenDup.Interop
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

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool ConvertStringSidToSid(string StringSid, out IntPtr Sid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcessWithToken(
            IntPtr hToken,
            LOGON_FLAGS dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            PROCESS_CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            in STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool EnumServicesStatus(
            IntPtr hSCManager,
            SERVICE_TYPE dwServiceType,
            SERVICE_CONTROL_STATE dwServiceState,
            IntPtr /* LPENUM_SERVICE_STATUS */ lpServices,
            int cbBufSize,
            out int pcbBytesNeeded,
            out int lpServicesReturned,
            IntPtr /* ref int */ lpResumeHandle);

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

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr OpenSCManager(
            string lpMachineName,
            string lpDatabaseName,
            ACCESS_MASK dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr OpenService(
            IntPtr hSCManager,
            string lpServiceName,
            ACCESS_MASK dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool QueryServiceStatusEx(
            IntPtr hService,
            SC_STATUS_TYPE InfoLevel,
            IntPtr lpBuffer,
            int cbBufSize,
            out int pcbBytesNeeded);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int SetEntriesInAcl(
            uint cCountOfExplicitEntries,
            IntPtr /* EXPLICIT_ACCESS[] */ pListOfExplicitEntries,
            IntPtr /* PACL */ OldAcl,
            out IntPtr /* PACL* */ NewAcl);

        /*
         * fwpuclnt.dll
         */
        [DllImport("fwpuclnt.dll")]
        public static extern NTSTATUS FwpmEngineClose0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
        public static extern NTSTATUS FwpmEngineOpen0(
            string serverName,
            RPC_C_AUTHN_TYPES authnService, // should be DEFAULT
            IntPtr /* in SEC_WINNT_AUTH_IDENTITY_W */ authIdentity,
            IntPtr /* in FWPM_SESSION0 */ session,
            out IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
        public static extern int FwpmIPsecTunnelAdd0(
            IntPtr engineHandle,
            FWPM_TUNNEL_FLAGS flags,
            in FWPM_PROVIDER_CONTEXT0 mainModePolicy,
            in FWPM_PROVIDER_CONTEXT0 tunnelPolicy,
            uint numFilterConditions,
            IntPtr /* FWPM_FILTER_CONDITION0[] */ filterConditions,
            IntPtr /* PSECURITY_DESCRIPTOR */ sd);

        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmIPsecTunnelDeleteByKey0(
            IntPtr engineHandle,
            in Guid key);

        /*
         * kernel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ProcessIdToSessionId(
            int dwProcessId,
            out int pSessionId);

        /*
         * ntdll.dll
         */
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateEvent(
            out IntPtr EventHandle,
            ACCESS_MASK DesiredAccess,
            IntPtr /* POBJECT_ATTRIBUTES */ ObjectAttributes,
            EVENT_TYPE EventType,
            BOOLEAN InitialState);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtDeviceIoControlFile(
            IntPtr FileHandle,
            IntPtr Event,
            IntPtr /* PIO_APC_ROUTINE */ ApcRoutine,
            IntPtr ApcContext,
            out IO_STATUS_BLOCK IoStatusBlock,
            uint IoControlCode,
            IntPtr InputBuffer,
            uint InputBufferLength,
            IntPtr OutputBuffer,
            uint OutputBufferLength);

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

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtSetEvent(IntPtr EventHandle, out int PreviousState);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtSetInformationToken(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtSetSecurityObject(
            IntPtr Handle,
            SECURITY_INFORMATION SecurityInformation,
            in SECURITY_DESCRIPTOR SecurityDescriptor);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWaitForSingleObject(
            IntPtr Handle,
            bool Alertable,
            in LARGE_INTEGER Timeout);

        /*
         * secur32.dll
         */
        [DllImport("secur32.dll")]
        public static extern NTSTATUS LsaEnumerateLogonSessions(
            out uint LogonSessionCount,
            out IntPtr /* PLUID* */ LogonSessionList);

        [DllImport("secur32.dll")]
        public static extern NTSTATUS LsaGetLogonSessionData(
            in LUID LogonId, // in LUID
            out IntPtr /* PSECURITY_LOGON_SESSION_DATA* */ ppLogonSessionData);

        [DllImport("secur32.dll")]
        public static extern NTSTATUS LsaFreeReturnBuffer(IntPtr Buffer);

        /*
         * user32.dll
         */
        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool CloseDesktop(IntPtr hDesktop);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool CloseWindowStation(IntPtr hWinSta);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr OpenDesktop(
            string lpszDesktop,
            DESKTOP_FLAGS dwFlags,
            bool fInherit,
            ACCESS_MASK dwDesiredAccess);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr OpenWindowStation(
            string lpszWinSta,
            bool fInherit,
            ACCESS_MASK dwDesiredAccess);

        /*
         * wtsapi32.dll
         */
        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern void WTSFreeMemory(IntPtr pMemory);


        [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool WTSQuerySessionInformation(
            IntPtr hServer,
            int SessionId,
            WTS_INFO_CLASS WTSInfoClass,
            out IntPtr ppBuffer,
            out int pBytesReturned);

        /*
         * ws2_32.dll
         */
        [DllImport("ws2_32.dll")]
        public static extern int bind(IntPtr s, in SOCKADDR_IN addr, int namelen);

        [DllImport("ws2_32.dll")]
        public static extern int closesocket(IntPtr s);

        [DllImport("ws2_32.dll")]
        public static extern int listen(IntPtr s, int backlog);

        [DllImport("ws2_32.dll")]
        public static extern IntPtr WSAAccept(
            IntPtr s,
            out SOCKADDR addr,
            ref int addrlen,
            IntPtr /* LPCONDITIONPROC callback type */ lpfnCondition,
            IntPtr dwCallbackData);

        [DllImport("ws2_32.dll")]
        public static extern int WSACleanup();

        [DllImport("ws2_32.dll")]
        public static extern int WSAStartup(
            short wVersionRequired, // 0x0202
            out WSADATA lpWSAData);

        [DllImport("ws2_32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr WSASocketW(
            int /* ADDRESS_FAMILY */ af,
            SOCKET_TYPE type,
            IPPROTO protocol,
            IntPtr /* in WSAPROTOCOL_INFOW */ lpProtocolInfo,
            SOCKET_GROUP g,
            WSA_FLAGS dwFlags);

        [DllImport("ws2_32.dll", CharSet = CharSet.Unicode)]
        public static extern int WSAStringToAddressW(
            string AddressString,
            int /* ADDRESS_FAMILY */ AddressFamily,
            IntPtr /* LPWSAPROTOCOL_INFOW */ lpProtocolInfo,
            IntPtr /* LPSOCKADDR */ lpAddress,
            ref int lpAddressLength);
    }
}
