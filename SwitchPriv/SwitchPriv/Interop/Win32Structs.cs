using System;
using System.Runtime.InteropServices;

namespace SwitchPriv.Interop
{
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

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    internal struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public int Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PRIVILEGE_SET
    {
        public int PrivilegeCount;
        public int Control;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privilege;

        public PRIVILEGE_SET(int _privilegeCount, int _control)
        {
            PrivilegeCount = _privilegeCount;
            Control = _control;
            Privilege = new LUID_AND_ATTRIBUTES[1];
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniquePID;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid; // PSID
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal class TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;

        public TOKEN_PRIVILEGES()
        {
            PrivilegeCount = 0;
            Privileges = new LUID_AND_ATTRIBUTES[1];
        }

        public TOKEN_PRIVILEGES(int nPrivilegeCount)
        {
            PrivilegeCount = nPrivilegeCount;
            Privileges = new LUID_AND_ATTRIBUTES[1];
        }
    }
}
