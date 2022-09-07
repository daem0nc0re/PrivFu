using System;
using System.Runtime.InteropServices;
using System.Text;

namespace S4uDelegator.Interop
{
    internal class KERB_S4U_LOGON : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct INNER_LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct INNER_KERB_S4U_LOGON
        {
            public int MessageType;
            public uint Flags;
            public INNER_LSA_UNICODE_STRING ClientUpn;
            public INNER_LSA_UNICODE_STRING ClientRealm;
        }

        private INNER_KERB_S4U_LOGON kerbS4uLogon =
            new INNER_KERB_S4U_LOGON();
        private readonly IntPtr pointer;
        private readonly int length;

        public KERB_S4U_LOGON(uint flags, string upn, string realm)
        {
            byte[] upnBytes = new byte[] { };
            byte[] realmBytes = new byte[] { };
            int KerbS4ULogon = 12;

            kerbS4uLogon.MessageType = KerbS4ULogon;
            kerbS4uLogon.Flags = flags;

            if (!string.IsNullOrEmpty(upn))
            {
                upnBytes = Encoding.Unicode.GetBytes(upn);
                kerbS4uLogon.ClientUpn.Length =
                    (ushort)upnBytes.Length;
                kerbS4uLogon.ClientUpn.MaximumLength =
                    (ushort)(upnBytes.Length + 2);
            }
            else
            {
                kerbS4uLogon.ClientUpn.Length = 0;
                kerbS4uLogon.ClientUpn.MaximumLength = 0;
            }

            if (!string.IsNullOrEmpty(realm))
            {
                realmBytes = Encoding.Unicode.GetBytes(realm);
                kerbS4uLogon.ClientRealm.Length =
                    (ushort)realmBytes.Length;
                kerbS4uLogon.ClientRealm.MaximumLength =
                    (ushort)(realmBytes.Length + 2);
            }
            else
            {
                kerbS4uLogon.ClientRealm.Length = 0;
                kerbS4uLogon.ClientRealm.MaximumLength = 0;
            }

            length = Marshal.SizeOf(kerbS4uLogon) +
                kerbS4uLogon.ClientUpn.MaximumLength +
                kerbS4uLogon.ClientRealm.MaximumLength;
            pointer = Marshal.AllocHGlobal(length);
            Marshal.Copy(new byte[length], 0, pointer, length);

            IntPtr pUpnString = new IntPtr(
                pointer.ToInt64() +
                Marshal.SizeOf(kerbS4uLogon));
            IntPtr pRealmString = new IntPtr(
                pUpnString.ToInt64() +
                kerbS4uLogon.ClientUpn.MaximumLength);

            if (!string.IsNullOrEmpty(upn))
            {
                Marshal.Copy(upnBytes, 0, pUpnString, upnBytes.Length);
                kerbS4uLogon.ClientUpn.Buffer = pUpnString;
            }
            else
            {
                kerbS4uLogon.ClientUpn.Buffer = IntPtr.Zero;
            }

            if (!string.IsNullOrEmpty(realm))
            {
                Marshal.Copy(realmBytes, 0, pRealmString, realmBytes.Length);
                kerbS4uLogon.ClientRealm.Buffer = pRealmString;
            }
            else
            {
                kerbS4uLogon.ClientRealm.Buffer = IntPtr.Zero;
            }

            Marshal.StructureToPtr(kerbS4uLogon, pointer, true);
        }

        public KERB_S4U_LOGON(string upn, string realm)
        {
            byte[] upnBytes = new byte[] { };
            byte[] realmBytes = new byte[] { };
            int KerbS4ULogon = 12;

            kerbS4uLogon.MessageType = KerbS4ULogon;
            kerbS4uLogon.Flags = 0;

            if (!string.IsNullOrEmpty(upn))
            {
                upnBytes = Encoding.Unicode.GetBytes(upn);
                kerbS4uLogon.ClientUpn.Length =
                    (ushort)upnBytes.Length;
                kerbS4uLogon.ClientUpn.MaximumLength =
                    (ushort)(upnBytes.Length + 2);
            }
            else
            {
                kerbS4uLogon.ClientUpn.Length = 0;
                kerbS4uLogon.ClientUpn.MaximumLength = 0;
            }

            if (!string.IsNullOrEmpty(realm))
            {
                realmBytes = Encoding.Unicode.GetBytes(realm);
                kerbS4uLogon.ClientRealm.Length =
                    (ushort)realmBytes.Length;
                kerbS4uLogon.ClientRealm.MaximumLength =
                    (ushort)(realmBytes.Length + 2);
            }
            else
            {
                kerbS4uLogon.ClientRealm.Length = 0;
                kerbS4uLogon.ClientRealm.MaximumLength = 0;
            }

            length = Marshal.SizeOf(kerbS4uLogon) +
                kerbS4uLogon.ClientUpn.MaximumLength +
                kerbS4uLogon.ClientRealm.MaximumLength;
            pointer = Marshal.AllocHGlobal(length);
            Marshal.Copy(new byte[length], 0, pointer, length);

            IntPtr pUpnString = new IntPtr(
                pointer.ToInt64() +
                Marshal.SizeOf(kerbS4uLogon));
            IntPtr pRealmString = new IntPtr(
                pUpnString.ToInt64() +
                kerbS4uLogon.ClientUpn.MaximumLength);

            if (!string.IsNullOrEmpty(upn))
            {
                Marshal.Copy(upnBytes, 0, pUpnString, upnBytes.Length);
                kerbS4uLogon.ClientUpn.Buffer = pUpnString;
            }
            else
            {
                kerbS4uLogon.ClientUpn.Buffer = IntPtr.Zero;
            }

            if (!string.IsNullOrEmpty(realm))
            {
                Marshal.Copy(realmBytes, 0, pRealmString, realmBytes.Length);
                kerbS4uLogon.ClientRealm.Buffer = pRealmString;
            }
            else
            {
                kerbS4uLogon.ClientRealm.Buffer = IntPtr.Zero;
            }

            Marshal.StructureToPtr(kerbS4uLogon, pointer, true);
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

    internal class MSV1_0_S4U_LOGON : IDisposable
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
        public uint LowPart;
        public uint HighPart;

        public LUID(uint _lowPart, uint _highPart)
        {
            LowPart = _lowPart;
            HighPart = _highPart;
        }

        public LUID(ulong value)
        {
            LowPart = (uint)(value & 0xFFFFFFFFUL);
            HighPart = (uint)(value >> 32);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    internal struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
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
        public uint PagedPoolLimit;
        public uint NonPagedPoolLimit;
        public uint MinimumWorkingSetSize;
        public uint MaximumWorkingSetSize;
        public uint PagefileLimit;
        public long TimeLimit;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid; // PSID
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
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
    internal struct TOKEN_GROUPS
    {
        public int GroupCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public SID_AND_ATTRIBUTES[] Groups;

        public TOKEN_GROUPS(int privilegeCount)
        {
            GroupCount = privilegeCount;
            Groups = new SID_AND_ATTRIBUTES[32];
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIVILEGES
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
    internal struct TOKEN_SOURCE
    {

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] SourceName;
        public LUID SourceIdentifier;

        public TOKEN_SOURCE(string name)
        {
            SourceName = new byte[8];
            Encoding.GetEncoding(1252).GetBytes(name, 0, name.Length, SourceName, 0);
            if (!NativeMethods.AllocateLocallyUniqueId(out SourceIdentifier))
                throw new System.ComponentModel.Win32Exception();
        }
    }
}
