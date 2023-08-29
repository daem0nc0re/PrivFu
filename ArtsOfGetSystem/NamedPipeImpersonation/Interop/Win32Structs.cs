using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NamedPipeImpersonation.Interop
{
    using SIZE_T = UIntPtr;

    [StructLayout(LayoutKind.Sequential)]
    internal struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public LARGE_INTEGER PerProcessUserTimeLimit;
        public LARGE_INTEGER PerJobUserTimeLimit;
        public JOB_OBJECT_LIMIT LimitFlags;
        public SIZE_T MinimumWorkingSetSize;
        public SIZE_T MaximumWorkingSetSize;
        public int ActiveProcessLimit;
        public UIntPtr Affinity;
        public int PriorityClass;
        public int SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public SIZE_T ProcessMemoryLimit;
        public SIZE_T JobMemoryLimit;
        public SIZE_T PeakProcessMemoryUsed;
        public SIZE_T PeakJobMemoryUsed;
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
    internal struct LSA_STRING
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
                throw new ArgumentException("String too long for AnsiString");
            }

            Length = (ushort)(str.Length);
            MaximumLength = (ushort)(str.Length + 1);
            Buffer = str;
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

    internal class MSV1_0_S4U_LOGON : IDisposable
    {
        public IntPtr Buffer { get; } = IntPtr.Zero;
        public int Length { get; } = 0;

        internal struct MSV1_0_S4U_LOGON_INNER
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
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct QUOTA_LIMITS
    {
        public SIZE_T PagedPoolLimit;
        public SIZE_T NonPagedPoolLimit;
        public SIZE_T MinimumWorkingSetSize;
        public SIZE_T MaximumWorkingSetSize;
        public SIZE_T PagefileLimit;
        public LARGE_INTEGER TimeLimit;
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
    internal class TOKEN_GROUPS
    {
        public uint GroupCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public SID_AND_ATTRIBUTES[] Groups;

        public TOKEN_GROUPS()
        {
            GroupCount = 0;
            Groups = new SID_AND_ATTRIBUTES[1];
        }

        public TOKEN_GROUPS(uint groupCount)
        {
            GroupCount = groupCount;
            Groups = new SID_AND_ATTRIBUTES[1];
        }
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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal struct TOKEN_SOURCE
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] SourceName;
        public LUID SourceIdentifier;

        public TOKEN_SOURCE(string sourceName)
        {
            var soureNameBytes = Encoding.ASCII.GetBytes(sourceName);
            int nSourceNameLength = (soureNameBytes.Length > 8) ? 8 : soureNameBytes.Length;
            SourceName = new byte[8];
            SourceIdentifier = new LUID();

            Buffer.BlockCopy(soureNameBytes, 0, SourceName, 0, nSourceNameLength);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_USER
    {
        public SID_AND_ATTRIBUTES User;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING : IDisposable
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
    internal struct USER_INFO_1
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
}
