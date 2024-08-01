using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace TokenDump.Interop
{
    using NTSTATUS = Int32;

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_CALLBACK_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public ACE_OBJECT_TYPE Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public ACE_OBJECT_TYPE Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_DENIED_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_DENIED_CALLBACK_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_DENIED_CALLBACK_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public ACE_OBJECT_TYPE Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_DENIED_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public ACE_OBJECT_TYPE Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACE_HEADER
    {
        public ACE_TYPE AceType;
        public ACE_FLAGS AceFlags;
        public short AceSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACL
    {
        public ACL_REVISION AclRevision;
        public byte Sbz1;
        public short AclSize;
        public short AceCount;
        public short Sbz2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct FWPM_DISPLAY_DATA0
    {
        public string name;
        public string description;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct FWPM_SESSION0
    {
        public Guid sessionKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public FWPM_SESSION_FLAGS flags;
        public uint txnWaitTimeoutInMSec;
        public int processId;
        public IntPtr /* PSID */ sid;
        public string username;
        public bool kernelMode;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct GENERIC_MAPPING
    {
        public ACCESS_MASK GenericRead;
        public ACCESS_MASK GenericWrite;
        public ACCESS_MASK GenericExecute;
        public ACCESS_MASK GenericAll;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct KEY_FULL_INFORMATION
    {
        public LARGE_INTEGER LastWriteTime;
        public uint TitleIndex;
        public uint ClassOffset;
        public uint ClassLength;
        public uint SubKeys;
        public uint MaxNameLen;
        public uint MaxClassLen;
        public uint Values;
        public uint MaxValueNameLen;
        public uint MaxValueDataLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public ushort[] /* WCHAR[] */ Class;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct KEY_NAME_INFORMATION
    {
        public uint NameLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public ushort[] /* WCHAR[] */ Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct KEY_NODE_INFORMATION
    {
        public LARGE_INTEGER LastWriteTime;
        public uint TitleIndex;
        public uint ClassOffset;
        public uint ClassLength;
        public uint NameLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public ushort[] /* WCHAR[] */ Name;
    }

    [StructLayout(LayoutKind.Explicit, Size = 8)]
    internal struct LARGE_INTEGER
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
            return ((long)High << 32) | (uint)Low;
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
    internal struct LSA_LAST_INTER_LOGON_INFO
    {
        public LARGE_INTEGER LastSuccessfulLogon;
        public LARGE_INTEGER LastFailedLogon;
        public uint FailedAttemptCountSinceLastSuccessfulLogon;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LSA_UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr buffer;

        public LSA_UNICODE_STRING(string s)
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

        public void SetBuffer(IntPtr _buffer)
        {
            buffer = _buffer;
        }

        public override string ToString()
        {
            if ((Length == 0) || (buffer == IntPtr.Zero))
                return null;
            else
                return Marshal.PtrToStringUni(buffer, Length / 2);
        }
    }

    [StructLayout(LayoutKind.Explicit, Size = 8, Pack = 4)]
    internal struct LUID
    {
        [FieldOffset(0)]
        public int LowPart;
        [FieldOffset(4)]
        public int HighPart;
        [FieldOffset(0)]
        public long QuadPart;

        public LUID(int _low, int _high)
        {
            QuadPart = 0L;
            LowPart = _low;
            HighPart = _high;
        }

        public LUID(long _quad)
        {
            LowPart = 0;
            HighPart = 0;
            QuadPart = _quad;
        }

        public long ToInt64()
        {
            return ((long)this.HighPart << 32) | (uint)this.LowPart;
        }

        public static LUID FromInt64(long value)
        {
            return new LUID
            {
                LowPart = (int)(value),
                HighPart = (int)((value >> 32))
            };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public int Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_ATTRIBUTES : IDisposable
    {
        public int Length;
        public IntPtr RootDirectory;
        private IntPtr objectName;
        public OBJECT_ATTRIBUTES_FLAGS Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;

        public OBJECT_ATTRIBUTES(
            string name,
            OBJECT_ATTRIBUTES_FLAGS attrs)
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
    internal struct OBJECT_DIRECTORY_INFORMATION
    {
        public UNICODE_STRING Name;
        public UNICODE_STRING TypeName;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_TYPE_INFORMATION
    {
        public UNICODE_STRING TypeName;
        public uint TotalNumberOfObjects;
        public uint TotalNumberOfHandles;
        public uint TotalPagedPoolUsage;
        public uint TotalNonPagedPoolUsage;
        public uint TotalNamePoolUsage;
        public uint TotalHandleTableUsage;
        public uint HighWaterNumberOfObjects;
        public uint HighWaterNumberOfHandles;
        public uint HighWaterPagedPoolUsage;
        public uint HighWaterNonPagedPoolUsage;
        public uint HighWaterNamePoolUsage;
        public uint HighWaterHandleTableUsage;
        public uint InvalidAttributes;
        public GENERIC_MAPPING GenericMapping;
        public uint ValidAccessMask;
        public BOOLEAN SecurityRequired;
        public BOOLEAN MaintainHandleCount;
        public byte TypeIndex; // since WINBLUE
        public byte ReservedByte;
        public uint PoolType;
        public uint DefaultPagedPoolCharge;
        public uint DefaultNonPagedPoolCharge;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_TYPES_INFORMATION
    {
        public uint NumberOfTypes;
        // OBJECT_TYPE_INFORMATION data entries are here.
        // Offset for OBJECT_TYPE_INFORMATION entries is IntPtr.Size
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SEC_WINNT_AUTH_IDENTITY_W
    {
        public string User;
        public uint UserLength;
        public string Domain;
        public uint DomainLength;
        public string Password;
        public uint PasswordLength;
        public SEC_WINNT_AUTH_IDENTITY_FLAGS Flags;

        public SEC_WINNT_AUTH_IDENTITY_W(string user, string domain, string password)
        {
            User = user;
            UserLength = (uint)user.Length;
            Domain = domain;
            DomainLength = (uint)domain.Length;
            Password = password;
            PasswordLength = (uint)password.Length;
            Flags = SEC_WINNT_AUTH_IDENTITY_FLAGS.UNICODE;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_LOGON_SESSION_DATA
    {
        public uint Size;
        public LUID LogonId;
        public LSA_UNICODE_STRING UserName;
        public LSA_UNICODE_STRING LogonDomain;
        public LSA_UNICODE_STRING AuthenticationPackage;
        public uint LogonType;
        public uint Session;
        public IntPtr /* PSID */ Sid;
        public LARGE_INTEGER LogonTime;
        public LSA_UNICODE_STRING LogonServer;
        public LSA_UNICODE_STRING DnsDomainName;
        public LSA_UNICODE_STRING Upn;
        public uint UserFlags;
        public LSA_LAST_INTER_LOGON_INFO LastLogonInfo;
        public LSA_UNICODE_STRING LogonScript;
        public LSA_UNICODE_STRING ProfilePath;
        public LSA_UNICODE_STRING HomeDirectory;
        public LSA_UNICODE_STRING HomeDirectoryDrive;
        public LARGE_INTEGER LogoffTime;
        public LARGE_INTEGER KickOffTime;
        public LARGE_INTEGER PasswordLastSet;
        public LARGE_INTEGER PasswordCanChange;
        public LARGE_INTEGER PasswordMustChange;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public int Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ACCESS_FILTER_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ALARM_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ALARM_CALLBACK_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ALARM_CALLBACK_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ALARM_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_AUDIT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_AUDIT_CALLBACK_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_AUDIT_CALLBACK_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_AUDIT_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_HANDLE_INFORMATION
    {
        public uint NumberOfHandles;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public SYSTEM_HANDLE_TABLE_ENTRY_INFO[] Handles;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
    {
        public ushort UniqueProcessId;
        public ushort CreatorBackTraceIndex;
        public byte ObjectTypeIndex;
        public byte HandleAttributes;
        public ushort HandleValue;
        public IntPtr Object;
        public uint GrantedAccess;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_MANDATORY_LABEL_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_PROCESS_TRUST_LABEL_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_RESOURCE_ATTRIBUTE_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_SCOPED_POLICY_ID_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct THREAD_BASIC_INFORMATION
    {
        public NTSTATUS ExitStatus;
        public IntPtr TebBaseAddress;
        public CLIENT_ID ClientId;
        public UIntPtr /* KAFFINITY */ AffinityMask;
        public int /* KPRIORITY */ Priority;
        public int /* KPRIORITY */ BasePriority;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_ACCESS_INFORMATION
    {
        public IntPtr /* PSID_AND_ATTRIBUTES_HASH */ SidHash;
        public IntPtr /* PSID_AND_ATTRIBUTES_HASH */ RestrictedSidHash;
        public IntPtr /* PTOKEN_PRIVILEGES */ Privileges;
        public LUID AuthenticationId;
        public TOKEN_TYPE TokenType;
        public SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
        public TOKEN_MANDATORY_POLICY MandatoryPolicy;
        public TokenFlags Flags;
        public uint AppContainerNumber;
        public IntPtr /* PSID */ PackageSid;
        public IntPtr /* PSID_AND_ATTRIBUTES_HASH */ CapabilitiesHash;
        public IntPtr /* PSID */ TrustLevelSid;
        public IntPtr /* PSECURITY_ATTRIBUTES_OPAQUE */ SecurityAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_APPCONTAINER_INFORMATION
    {
        public IntPtr /* PSID */ TokenAppContainer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_DEFAULT_DACL
    {
        public IntPtr /* PACL */ DefaultDacl;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_GROUPS
    {
        public int GroupCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public SID_AND_ATTRIBUTES[] Groups;

        public TOKEN_GROUPS(int nGroupCount)
        {
            GroupCount = nGroupCount;
            Groups = new SID_AND_ATTRIBUTES[1];
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_MANDATORY_POLICY
    {
        public TOKEN_MANDATORY_POLICY_FLAGS Policy;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_ORIGIN
    {
        public LUID OriginatingLogonSession;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_OWNER
    {
        public IntPtr Owner;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIMARY_GROUP
    {
        public IntPtr PrimaryGroup;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PROCESS_TRUST_LEVEL
    {
        public IntPtr TrustLevelSid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE
    {
        public ulong Version;
        public UNICODE_STRING Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_SECURITY_ATTRIBUTE_V1
    {
        public UNICODE_STRING Name;
        public TOKEN_SECURITY_ATTRIBUTE_TYPE ValueType;
        public ushort Reserved;
        public TOKEN_SECURITY_ATTRIBUTE_FLAGS Flags;
        public uint ValueCount;
        public IntPtr Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_SECURITY_ATTRIBUTES_INFORMATION
    {
        public ushort Version;
        public ushort Reserved;
        public uint AttributeCount;
        public IntPtr /* PTOKEN_SECURITY_ATTRIBUTE_V1 */ pAttributeV1;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal struct TOKEN_SOURCE
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] SourceName;
        public LUID SourceIdentifier;

        public TOKEN_SOURCE(string sourceName)
        {
            var soureNameBytes = Encoding.ASCII.GetBytes(sourceName);
            int nSourceNameLength = (soureNameBytes.Length > 8) ? 8 : soureNameBytes.Length;
            SourceName = new byte[8];
            SourceIdentifier = new LUID();

            Buffer.BlockCopy(soureNameBytes, 0, SourceName, 0, nSourceNameLength);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_STATISTICS
    {
        public LUID TokenId;
        public LUID AuthenticationId;
        public LARGE_INTEGER ExpirationTime;
        public TOKEN_TYPE TokenType;
        public SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
        public int DynamicCharged;
        public int DynamicAvailable;
        public int GroupCount;
        public int PrivilegeCount;
        public LUID ModifiedId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_USER
    {
        public SID_AND_ATTRIBUTES User;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING : IDisposable
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

        public void SetBuffer(IntPtr _buffer)
        {
            buffer = _buffer;
        }

        public override string ToString()
        {
            if ((Length == 0) || (buffer == IntPtr.Zero))
                return null;
            else
                return Marshal.PtrToStringUni(buffer, Length / 2);
        }
    }
}
