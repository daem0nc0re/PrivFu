using System;
using System.Runtime.InteropServices;

namespace UserRightsUtil.Interop
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public int Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LSA_UNICODE_STRING
    {
        ushort Length;
        ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Buffer;

        public LSA_UNICODE_STRING(string str)
        {
            Length = 0;
            MaximumLength = 0;
            Buffer = null;
            SetString(str);
        }

        public void SetString(string str)
        {
            if (str.Length > (ushort.MaxValue - 2) / 2)
            {
                throw new ArgumentException("String too long for UnicodeString");
            }
            Length = (ushort)(str.Length * 2);
            MaximumLength = (ushort)((str.Length * 2) + 2);
            Buffer = str;
        }
    }
}
