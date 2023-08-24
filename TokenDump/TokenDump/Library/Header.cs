using System;
using System.Runtime.InteropServices;
using TokenDump.Interop;

namespace TokenDump.Library
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct AceInformation
    {
        public string AccountName;
        public string AccountSid;
        public ACCESS_MASK AccessMask;
        public ACE_FLAGS Flags;
        public ACE_TYPE Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct BriefTokenInformation
    {
        public int ProcessId;
        public int ThreadId;
        public int SessionId;
        public IntPtr Handle;
        public string Integrity;
        public string ProcessName;
        public string ImageFilePath;
        public string TokenUserName;
        public TOKEN_TYPE TokenType;
        public SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
        public bool IsAppContainer;
        public bool IsRestricted;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct VerboseTokenInformation
    {
        public int ProcessId;
        public int ThreadId;
        public int SessionId;
        public IntPtr Handle;
        public IntPtr SecurityAttributesBuffer;
        public string ProcessName;
        public string ImageFilePath;
        public string CommandLine;
        public string Integrity;
        public string TokenUserName;
        public string TokenUserSid;
        public string TokenOwnerName;
        public string TokenOwnerSid;
        public string TokenPrimaryGroupName;
        public string TokenPrimaryGroupSid;
        public string TrustLabel;
        public string TrustLabelSid;
        public string AppContainerName;
        public string AppContainerSid;
        public uint AppContainerNumber;
        public TOKEN_ELEVATION_TYPE ElevationType;
        public TOKEN_MANDATORY_POLICY_FLAGS MandatoryPolicy;
        public TOKEN_ORIGIN TokenOrigin;
        public TOKEN_SOURCE TokenSource;
        public TOKEN_STATISTICS TokenStatistics;
        public TokenFlags TokenFlags;
        public bool IsAppContainer;
        public bool IsElevated;
        public bool IsLinkedToken;
        public bool HasLinkedToken;
    }
}
