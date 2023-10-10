using System;
using System.Runtime.InteropServices;

namespace EfsPotato.Interop
{
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
    internal struct OVERLAPPED
    {
        public UIntPtr Internal;
        public UIntPtr InternalHigh;
        public OVERLAPPED_INNER Data;
        public IntPtr hEvent;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct OVERLAPPED_INNER
    {
        [FieldOffset(0)]
        public int Offset;

        [FieldOffset(0)]
        public IntPtr Pointer;

        [FieldOffset(4)]
        public int OffsetHigh;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr /* PSECURITY_DESCRIPTOR */ lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_DESCRIPTOR
    {
        public byte Revision;
        public byte Sbz1;
        public SECURITY_DESCRIPTOR_CONTROL Control;
        public int /* PSID */ Owner; // In this program, relative pointer
        public int /* PSID */ Group; // In this program, relative pointer
        public int /* PACL */ Sacl; // In this program, relative pointer
        public int /* PACL */ Dacl; // In this program, relative pointer
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public int Attributes;
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
}
