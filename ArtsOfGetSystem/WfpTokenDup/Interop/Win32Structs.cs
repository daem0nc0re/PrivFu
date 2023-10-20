using System;
using System.Runtime.InteropServices;

namespace WfpTokenDup.Interop
{
    using NTSTATUS = Int32;

    [StructLayout(LayoutKind.Sequential)]
    internal struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct CLIENT_CALL_RETURN
    {
        [FieldOffset(0)]
        public IntPtr /* void* */ Pointer;

        [FieldOffset(0)]
        public IntPtr /* LONG_PTR */ Simple;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    internal struct ENUM_SERVICE_STATUS
    {
        public string lpServiceName;
        public string lpDisplayName;
        public SERVICE_STATUS ServiceStatus;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct EXPLICIT_ACCESS
    {
        public ACCESS_MASK grfAccessPermissions;
        public ACCESS_MODE grfAccessMode;
        public INHERITANCE_FLAGS grfInheritance;
        public TRUSTEE Trustee;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_BYTE_BLOB
    {
        public int Size;
        public IntPtr Data; // Pointer to null-terminated key unicode string data
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_BYTE_ARRAY16
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] byteArray16;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_CONDITION_VALUE0
    {
        public FWP_DATA_TYPE Type;
        public FWP_CONDITION_VALUE_UNION Value;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct FWP_CONDITION_VALUE_UNION
    {
        [FieldOffset(0)]
        public byte uint8;

        [FieldOffset(0)]
        public ushort uint16;

        [FieldOffset(0)]
        public uint uint32;

        [FieldOffset(0)]
        public IntPtr /* UINT64* */ uint64;

        [FieldOffset(0)]
        public byte int8;

        [FieldOffset(0)]
        public short int16;

        [FieldOffset(0)]
        public int int32;

        [FieldOffset(0)]
        public IntPtr /* INT64* */ int64;

        [FieldOffset(0)]
        public float float32;

        [FieldOffset(0)]
        public IntPtr /* double* */ double64;

        [FieldOffset(0)]
        public IntPtr /* FWP_BYTE_ARRAY16* */ byteArray16;

        [FieldOffset(0)]
        public IntPtr /* FWP_BYTE_BLOB* */ byteBlob;

        [FieldOffset(0)]
        public IntPtr /* SID* */ sid;

        [FieldOffset(0)]
        public IntPtr /* FWP_BYTE_BLOB* */ sd;

        [FieldOffset(0)]
        public IntPtr /* FWP_TOKEN_INFORMATION* */ tokenInformation;

        [FieldOffset(0)]
        public IntPtr /* FWP_BYTE_BLOB* */ tokenAccessInformation;

        [FieldOffset(0)]
        public IntPtr /* LPWSTR */ unicodeString;

        [FieldOffset(0)]
        public IntPtr /* FWP_BYTE_ARRAY6* */ byteArray6;

        [FieldOffset(0)]
        public IntPtr /* FWP_V4_ADDR_AND_MASK* */ v4AddrMask;

        [FieldOffset(0)]
        public IntPtr /* FWP_V6_ADDR_AND_MASK* */ v6AddrMask;

        [FieldOffset(0)]
        public IntPtr /* FWP_RANGE0* */ rangeValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_CLASSIFY_OPTION0
    {
        public FWP_CLASSIFY_OPTION_TYPE type;
        public FWP_VALUE0 value;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_CLASSIFY_OPTIONS0
    {
        public uint numOptions;
        public IntPtr /* FWPM_CLASSIFY_OPTION0* */ options;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct FWPM_DISPLAY_DATA0
    {
        public string name;
        public string description;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_FILTER_CONDITION0
    {
        public Guid fieldKey;
        public FWP_MATCH_TYPE matchType;
        public FWP_CONDITION_VALUE0 conditionValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_PROVIDER_CONTEXT0
    {
        public Guid providerContextKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public FWPM_PROVIDER_CONTEXT_FLAGS flags;
        public IntPtr /* GUID* */ providerKey;
        public FWP_BYTE_BLOB providerData;
        public FWPM_PROVIDER_CONTEXT_TYPE type;
        public FWPM_PROVIDER_CONTEXT0_UNION data;
        public ulong providerContextId;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct FWPM_PROVIDER_CONTEXT0_UNION
    {
        [FieldOffset(0)]
        public IntPtr /* IPSEC_KEYING_POLICY0* */ keyingPolicy;

        [FieldOffset(0)]
        public IntPtr /* IPSEC_TRANSPORT_POLICY0* */ ikeQmTransportPolicy;

        [FieldOffset(0)]
        public IntPtr /* IPSEC_TUNNEL_POLICY0* */ ikeQmTunnelPolicy;

        [FieldOffset(0)]
        public IntPtr /* IPSEC_TRANSPORT_POLICY0* */ authipQmTransportPolicy;

        [FieldOffset(0)]
        public IntPtr /* IPSEC_TUNNEL_POLICY0* */ authipQmTunnelPolicy;

        [FieldOffset(0)]
        public IntPtr /* IKEEXT_POLICY0* */ ikeMmPolicy;

        [FieldOffset(0)]
        public IntPtr /* IKEEXT_POLICY0* */ authIpMmPolicy;

        [FieldOffset(0)]
        public IntPtr /* FWP_BYTE_BLOB* */ dataBuffer;

        [FieldOffset(0)]
        public IntPtr /* FWPM_CLASSIFY_OPTIONS0* */ classifyOptions;
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
    internal struct FWP_VALUE0
    {
        public FWP_DATA_TYPE type;
        public FWP_VALUE0_UNION value;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct FWP_VALUE0_UNION
    {
        [FieldOffset(0)]
        public byte uint8;

        [FieldOffset(0)]
        public ushort uint16;

        [FieldOffset(0)]
        public uint uint32;

        [FieldOffset(0)]
        public IntPtr /* UINT64* */ uint64;

        [FieldOffset(0)]
        public byte int8;

        [FieldOffset(0)]
        public short int16;

        [FieldOffset(0)]
        public int int32;

        [FieldOffset(0)]
        public IntPtr /* INT64* */ int64;

        [FieldOffset(0)]
        public float float32;

        [FieldOffset(0)]
        public IntPtr /* double* */ double64;

        [FieldOffset(0)]
        public IntPtr /* FWP_BYTE_ARRAY16* */ byteArray16;

        [FieldOffset(0)]
        public IntPtr /* FWP_BYTE_BLOB* */ byteBlob;

        [FieldOffset(0)]
        public IntPtr /* SID* */ sid;

        [FieldOffset(0)]
        public IntPtr /* FWP_BYTE_BLOB* */ sd;

        [FieldOffset(0)]
        public IntPtr /* FWP_TOKEN_INFORMATION* */ tokenInformation;

        [FieldOffset(0)]
        public IntPtr /* FWP_BYTE_BLOB* */ tokenAccessInformation;

        [FieldOffset(0)]
        public IntPtr /* LPWSTR */ unicodeString;

        [FieldOffset(0)]
        public IntPtr /* FWP_BYTE_ARRAY6* */ byteArray6;
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
    internal struct IKEEXT_AUTHENTICATION_METHOD0
    {
        public IKEEXT_AUTHENTICATION_METHOD_TYPE authenticationMethodType;
        public IKEEXT_AUTHENTICATION_METHOD0_UNION data;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct IKEEXT_AUTHENTICATION_METHOD0_UNION
    {
        [FieldOffset(0)]
        public IKEEXT_PRESHARED_KEY_AUTHENTICATION0 presharedKeyAuthentication;

        [FieldOffset(0)]
        public IKEEXT_CERTIFICATE_AUTHENTICATION0 certificateAuthentication;

        [FieldOffset(0)]
        public IKEEXT_KERBEROS_AUTHENTICATION0 kerberosAuthentication;

        [FieldOffset(0)]
        public IKEEXT_NTLM_V2_AUTHENTICATION0 ntlmV2Authentication;

        [FieldOffset(0)]
        public IKEEXT_CERTIFICATE_AUTHENTICATION0 sslAuthentication;

        // [FieldOffset(0)]
        // public IKEEXT_IPV6_CGA_AUTHENTICATION0 cgaAuthentication;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IKEEXT_CERT_ROOT_CONFIG0
    {
        public FWP_BYTE_BLOB certData;
        public IKEEXT_CERT_FLAGS flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IKEEXT_CERTIFICATE_AUTHENTICATION0
    {
        public IKEEXT_CERT_CONFIG_TYPE inboundConfigType;
        public IKEEXT_CERT_ROOT_CONFIG0_INOUT inboundConfig;
        public IKEEXT_CERT_CONFIG_TYPE outboundConfigType;
        public IKEEXT_CERT_ROOT_CONFIG0_INOUT outboundConfig;
        public IKEEXT_CERT_AUTH_FLAGS flags;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct IKEEXT_CERT_ROOT_CONFIG0_INOUT
    {
        [FieldOffset(0)]
        public IKEEXT_CERT_ROOT_CONFIG0_INOUT_INNER RootConfig;

        [FieldOffset(0)]
        public IntPtr /* IKEEXT_CERT_ROOT_CONFIG0* */ EnterpriseStoreConfig;

        [FieldOffset(0)]
        public IntPtr /* IKEEXT_CERT_ROOT_CONFIG0* */ TrustedRootStoreConfig;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IKEEXT_CERT_ROOT_CONFIG0_INOUT_INNER
    {
        public uint ArraySize;
        public IntPtr /* IKEEXT_CERT_ROOT_CONFIG0* */ Array;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IKEEXT_CIPHER_ALGORITHM0
    {
        public IKEEXT_CIPHER_TYPE algoIdentifier;
        public uint keyLen;
        public uint rounds;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IKEEXT_EM_POLICY0
    {
        public uint numAuthenticationMethods;
        public IntPtr /* IKEEXT_AUTHENTICATION_METHOD0* */ authenticationMethods;
        public IKEEXT_AUTHENTICATION_IMPERSONATION_TYPE initiatorImpersonationType;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IKEEXT_INTEGRITY_ALGORITHM0
    {
        public IKEEXT_INTEGRITY_TYPE algoIdentifier;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IKEEXT_IPV6_CGA_AUTHENTICATION0
    {
        public IntPtr /* wchar_t* */ keyContainerName;
        public IntPtr /* wchar_t* */ cspName;
        public uint cspType;
        public FWP_BYTE_ARRAY16 cgaModifier;
        public byte cgaCollisionCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IKEEXT_KERBEROS_AUTHENTICATION0
    {
        public IKEEXT_KERB_AUTH_FLAGS flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IKEEXT_NTLM_V2_AUTHENTICATION0
    {
        public IKEEXT_NTLM_V2_AUTH_FLAGS flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IKEEXT_PRESHARED_KEY_AUTHENTICATION0
    {
        public FWP_BYTE_BLOB presharedKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IKEEXT_POLICY0
    {
        public uint softExpirationTime;
        public uint numAuthenticationMethods;
        public IntPtr /* IKEEXT_AUTHENTICATION_METHOD0* */ authenticationMethods;
        public IKEEXT_AUTHENTICATION_IMPERSONATION_TYPE initiatorImpersonationType;
        public uint numIkeProposals;
        public IntPtr /* IKEEXT_PROPOSAL0* */ ikeProposals;
        public uint flags;
        public uint maxDynamicFilters;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IKEEXT_PROPOSAL0
    {
        public IKEEXT_CIPHER_ALGORITHM0 cipherAlgorithm;
        public IKEEXT_INTEGRITY_ALGORITHM0 integrityAlgorithm;
        public uint maxLifetimeSeconds;
        public IKEEXT_DH_GROUP dhGroup;
        public uint quickModeLimit;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IO_STATUS_BLOCK
    {
        public NTSTATUS Status;
        public UIntPtr Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IPSEC_AUTH_AND_CIPHER_TRANSFORM0
    {
        public IPSEC_AUTH_TRANSFORM0 authTransform;
        public IPSEC_CIPHER_TRANSFORM0 cipherTransform;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IPSEC_AUTH_TRANSFORM_ID0
    {
        public IPSEC_AUTH_TYPE authType;
        public IPSEC_AUTH_CONFIG authConfig;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IPSEC_AUTH_TRANSFORM0
    {
        public IPSEC_AUTH_TRANSFORM_ID0 authTransformId;
        public IntPtr /* IPSEC_CRYPTO_MODULE_ID* (GUID*) */ cryptoModuleId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IPSEC_CIPHER_TRANSFORM_ID0
    {
        public IPSEC_CIPHER_TYPE cipherType;
        public IPSEC_CIPHER_CONFIG cipherConfig;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IPSEC_CIPHER_TRANSFORM0
    {
        public IPSEC_CIPHER_TRANSFORM_ID0 cipherTransformId;
        public IntPtr /* IPSEC_CRYPTO_MODULE_ID* (GUID*) */ cryptoModuleId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IPSEC_KEYING_POLICY0_
    {
        public uint numKeyMods;
        public IntPtr /* GUID* */ keyModKeys;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IPSEC_PROPOSAL0
    {
        public IPSEC_SA_LIFETIME0 lifetime;
        public uint numSaTransforms;
        public IntPtr /* IPSEC_SA_TRANSFORM0* */ saTransforms;
        public IPSEC_PFS_GROUP pfsGroup;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IPSEC_SA_IDLE_TIMEOUT0
    {
        public uint idleTimeoutSeconds;
        public uint idleTimeoutSecondsFailOver;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IPSEC_SA_LIFETIME0
    {
        public uint lifetimeSeconds;
        public uint lifetimeKilobytes;
        public uint lifetimePackets;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IPSEC_SA_TRANSFORM0
    {
        public IPSEC_TRANSFORM_TYPE ipsecTransformType;
        public IPSEC_SA_TRANSFORM0_UNION data;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct IPSEC_SA_TRANSFORM0_UNION
    {
        [FieldOffset(0)]
        public IntPtr /* IPSEC_AUTH_TRANSFORM0* */ ahTransform;

        [FieldOffset(0)]
        public IntPtr /* IPSEC_AUTH_TRANSFORM0* */ espAuthTransform;

        [FieldOffset(0)]
        public IntPtr /* IPSEC_CIPHER_TRANSFORM0* */ espCipherTransform;

        [FieldOffset(0)]
        public IntPtr /* IPSEC_AUTH_AND_CIPHER_TRANSFORM0* */ espAuthAndCipherTransform;

        [FieldOffset(0)]
        public IntPtr /* IPSEC_AUTH_TRANSFORM0* */ espAuthFwTransform;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IPSEC_TRANSPORT_POLICY0
    {
        public uint numIpsecProposals;
        public IntPtr /* IPSEC_PROPOSAL0* */ ipsecProposals;
        public IPSEC_POLICY_FLAGS flags;
        public uint ndAllowClearTimeoutSeconds;
        public IPSEC_SA_IDLE_TIMEOUT0 saIdleTimeout;
        public IntPtr /* IKEEXT_EM_POLICY0* */ emPolicy;
    }

    [StructLayout(LayoutKind.Explicit, Size = 36)]
    internal struct IPSEC_TUNNEL_ENDPOINTS0_V4
    {
        [FieldOffset(0)]
        public FWP_IP_VERSION ipVersion;

        [FieldOffset(4)]
        public uint localV4Address;

        [FieldOffset(20)]
        public uint remoteV4Address;
    }

    [StructLayout(LayoutKind.Sequential, Size = 36)]
    internal struct IPSEC_TUNNEL_ENDPOINTS0_V6
    {
        public FWP_IP_VERSION ipVersion;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localV6Address;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] remoteV6Address;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IPSEC_TUNNEL_POLICY0_V4
    {
        public IPSEC_POLICY_FLAGS flags;
        public uint numIpsecProposals;
        public IntPtr /* IPSEC_PROPOSAL0* */ ipsecProposals;
        public IPSEC_TUNNEL_ENDPOINTS0_V4 tunnelEndpoints;
        public IPSEC_SA_IDLE_TIMEOUT0 saIdleTimeout;
        public IntPtr /* IKEEXT_EM_POLICY0* */ emPolicy;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IPSEC_TUNNEL_POLICY0_V6
    {
        public IPSEC_POLICY_FLAGS flags;
        public uint numIpsecProposals;
        public IntPtr /* IPSEC_PROPOSAL0* */ ipsecProposals;
        public IPSEC_TUNNEL_ENDPOINTS0_V6 tunnelEndpoints;
        public IPSEC_SA_IDLE_TIMEOUT0 saIdleTimeout;
        public IntPtr /* IKEEXT_EM_POLICY0* */ emPolicy;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct LARGE_INTEGER
    {
        [FieldOffset(0)]
        public int Low;
        [FieldOffset(4)]
        public int High;
        [FieldOffset(0)]
        public long QuadPart;

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
        private IntPtr buffer; // Avoid name conflict with Buffer class

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

        public override string ToString()
        {
            if ((Length == 0) || (buffer == IntPtr.Zero))
                return null;
            else
                return Marshal.PtrToStringUni(buffer, Length / 2);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID
    {
        public int LowPart;
        public int HighPart;

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
    internal struct OBJECT_NAME_INFORMATION
    {
        public UNICODE_STRING Name;
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

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
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
    internal struct SECURITY_DESCRIPTOR
    {
        public byte Revision;
        public byte Sbz1;
        public SECURITY_DESCRIPTOR_CONTROL Control;
        public IntPtr Owner; // PSID
        public IntPtr Group; // PSID
        public IntPtr Sacl; // PACL
        public IntPtr Dacl; // PACL
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
    internal struct SERVICE_STATUS
    {
        public SERVICE_TYPE dwServiceType;
        public SERVICE_STATE dwCurrentState;
        public SERVICE_ACCEPT dwControlsAccepted;
        public int dwWin32ExitCode;
        public int dwServiceSpecificExitCode;
        public int dwCheckPoint;
        public int dwWaitHint;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_STATUS_PROCESS
    {
        public SERVICE_TYPE dwServiceType;
        public SERVICE_STATE dwCurrentState;
        public SERVICE_ACCEPT dwControlsAccepted;
        public int dwWin32ExitCode;
        public int dwServiceSpecificExitCode;
        public int dwCheckPoint;
        public int dwWaitHint;
        public int dwProcessId;
        public SERVICE_FLAGS dwServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public int Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SOCKADDR
    {
        public ADDRESS_FAMILY sa_family;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 14)]
        public byte[] sa_data;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SOCKADDR_IN
    {
        public ADDRESS_FAMILY sin_family;
        public ushort sin_port;
        public int sin_addr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] sin_zero;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    internal struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
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
    internal struct TOKEN_GROUPS
    {
        public int GroupCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public SID_AND_ATTRIBUTES[] Groups;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;

        public TOKEN_PRIVILEGES(int nPrivilegeCount)
        {
            PrivilegeCount = nPrivilegeCount;
            Privileges = new LUID_AND_ATTRIBUTES[1];
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_USER
    {
        public SID_AND_ATTRIBUTES User;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TRUSTEE
    {
        public IntPtr /* TRUSTEE */ pMultibleTrustee;
        public MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
        public TRUSTEE_FORM TrusteeForm;
        public TRUSTEE_TYPE TrusteeType;
        public IntPtr ptstrName;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr buffer; // Avoid name conflict with Buffer class

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

    [StructLayout(LayoutKind.Sequential)]
    internal struct WFP_TOKEN_INFORMATION
    {
        public UIntPtr Pid;
        public IntPtr Token;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WSAPROTOCOL_INFOW
    {
        public WSA_SERVICE_FLAGS1 dwServiceFlags1;
        public int dwServiceFlags2; // Reserved Parameter
        public int dwServiceFlags3; // Reserved Parameter
        public int dwServiceFlags4; // Reserved Parameter
        public WSA_PROVIDOR_FLAGS dwProviderFlags;
        public Guid ProviderId;
        public int dwCatalogEntryId;
        public WSAPROTOCOLCHAIN ProtocolChain;
        public int iVersion;
        public ADDRESS_FAMILY iAddressFamily;
        public int iMaxSockAddr;
        public int iMinSockAddr;
        public SOCKET_TYPE iSocketType;
        public IPPROTO iProtocol;
        public int iProtocolMaxOffset;
        public int iNetworkByteOrder;
        public int iSecurityScheme;
        public int dwMessageSize;
        public int dwProviderReserved;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] szProtocol;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WSADATA
    {
        public short wVersion;
        public short wHighVersion;
        public ushort iMaxSockets;
        public ushort iMaxUdpDg;
        public IntPtr lpVendorInfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 257)]
        public byte[] szDescription;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 130)]
        public byte[] szSystemStatus;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WSAPROTOCOLCHAIN
    {
        public int ChainLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
        public int[] ChainEntries;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct XMIT_ROUTINE_QUINTUPLE
    {
        public IntPtr /* XMIT_HELPER_ROUTINE */ pfnTranslateToXmit;
        public IntPtr /* XMIT_HELPER_ROUTINE */ pfnTranslateFromXmit;
        public IntPtr /* XMIT_HELPER_ROUTINE */ pfnFreeXmit;
        public IntPtr /* XMIT_HELPER_ROUTINE */ pfnFreeInst;
    }
}
