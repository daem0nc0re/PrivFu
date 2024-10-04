using System;
using System.Runtime.InteropServices;

namespace TokenStealing.Interop
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
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
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
    internal class TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_USER
    {
        public SID_AND_ATTRIBUTES User;
    }
}
