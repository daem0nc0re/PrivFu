using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Net.NetworkInformation;

namespace SeSystemEnvironmentPrivilegePoC
{
    class SeSystemEnvironmentPrivilegePoC
    {
        /*
         * P/Invoke : Enums
         */
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

        /*
         * P/Invoke : Structs
         */
        [StructLayout(LayoutKind.Sequential)]
        struct OSVERSIONINFOW
        {
            public uint dwOSVersionInfoSize;
            public uint dwMajorVersion;
            public uint dwMinorVersion;
            public uint dwBuildNumber;
            public uint dwPlatformId;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
            public byte[] szCSDVersion;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct VARIABLE_NAME
        {
            public uint NextEntryOffset;
            public Guid VendorGuid;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public short[] Name;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct VARIABLE_NAME_AND_VALUE
        {
            public uint NextEntryOffset;
            public uint ValueOffset;
            public uint ValueLength;
            public uint Attributes;
            public Guid VendorGuid;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public short[] Name;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public byte[] Value;
        }

        /*
         * P/Invoke : Win32 APIs
         */
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern int FormatMessage(
            FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("ntdll.dll")]
        static extern int NtEnumerateSystemEnvironmentValuesEx(
            uint InformationClass,
            IntPtr Buffer,
            ref uint BufferLength);

        [DllImport("ntdll.dll")]
        static extern int RtlGetVersion(out OSVERSIONINFOW lpVersionInformation);

        /*
         * Windows Consts
         */
        const int STATUS_SUCCESS = 0;
        static readonly int STATUS_BUFFER_TOO_SMALL = Convert.ToInt32("0xC0000023", 16);
        // const uint VARIABLE_INFORMATION_NAMES = 1u;
        const uint VARIABLE_INFORMATION_VALUES = 2u;

        /*
         * User defined functions
         */
        static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            int nReturnedLength;
            int nSizeMesssage = 256;
            var message = new StringBuilder(nSizeMesssage);
            var dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            var pNtdll = IntPtr.Zero;

            if (isNtStatus)
            {
                foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
                {
                    if (CompareIgnoreCase(Path.GetFileName(module.FileName), "ntdll.dll"))
                    {
                        pNtdll = module.BaseAddress;
                        dwFlags |= FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE;
                        break;
                    }
                }
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
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            else
                return string.Format("[ERROR] Code 0x{0} : {1}", code.ToString("X8"), message.ToString().Trim());
        }


        static bool GetSystemEnvironmentVariables()
        {
            int ntstatus;
            IntPtr pOffset;
            IntPtr pName;
            IntPtr pValue;
            VARIABLE_NAME_AND_VALUE info;
            uint nBufferLength = 0;
            int count = 0;
            var nNameOffset = Marshal.OffsetOf(typeof(VARIABLE_NAME_AND_VALUE), "Name").ToInt32();
            var pInfoBuffer = IntPtr.Zero;

            do
            {
                Console.WriteLine("[>] Trying to enumerate firmware environment variables in this machine.");

                ntstatus = NtEnumerateSystemEnvironmentValuesEx(
                    VARIABLE_INFORMATION_VALUES,
                    IntPtr.Zero,
                    ref nBufferLength);

                if (ntstatus != STATUS_BUFFER_TOO_SMALL)
                {
                    Console.WriteLine("[-] Failed to enumerate firmware environment values.");
                    Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(ntstatus, true));
                    break;
                }

                pInfoBuffer = Marshal.AllocHGlobal((int)nBufferLength);
                ntstatus = NtEnumerateSystemEnvironmentValuesEx(
                    VARIABLE_INFORMATION_VALUES,
                    pInfoBuffer,
                    ref nBufferLength);

                if (ntstatus != STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to enumerate firmware environment values.");
                    Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(ntstatus, true));
                    break;
                }

                pOffset = pInfoBuffer;

                do
                {
                    info = (VARIABLE_NAME_AND_VALUE)Marshal.PtrToStructure(pOffset, typeof(VARIABLE_NAME_AND_VALUE));

                    if (Environment.Is64BitProcess)
                    {
                        pOffset = new IntPtr(pOffset.ToInt64() + info.NextEntryOffset);
                        pName = new IntPtr(pOffset.ToInt64() + nNameOffset);
                        pValue = new IntPtr(pOffset.ToInt64() + info.ValueOffset);
                    }
                    else
                    {
                        pOffset = new IntPtr(pOffset.ToInt32() + (int)info.NextEntryOffset);
                        pName = new IntPtr(pOffset.ToInt32() + nNameOffset);
                        pValue = new IntPtr(pOffset.ToInt32() + (int)info.ValueOffset);
                    }

                    Console.WriteLine();
                    Console.WriteLine("Vendor GUID : {0}", info.VendorGuid);
                    Console.WriteLine("Name        : {0}", Marshal.PtrToStringUni(pName));
                    Console.WriteLine("Value       :\n");
                    HexDump.Dump(pValue, info.ValueLength, 1);
                    count++;
                } while (info.NextEntryOffset > 0);
            } while (false);

            if (pInfoBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(pInfoBuffer);

            Console.WriteLine();
            Console.WriteLine("[*] Enumeration is completed.");
            Console.WriteLine("[*] {0} variables are found.\n", count);

            return (ntstatus == STATUS_SUCCESS);
        }


        static void Main()
        {
            int ntstatus = RtlGetVersion(out OSVERSIONINFOW versionInfo);

            if (ntstatus == 0)
            {
                if (((versionInfo.dwMajorVersion == 10) && (versionInfo.dwBuildNumber >= 17134)) ||
                    (versionInfo.dwMajorVersion > 10))
                {
                    Console.WriteLine("[*] If you have SeSystemEnvironmentPrivilege, you can manipulate firmware environment variables.");
                    Console.WriteLine("[*] This PoC tries to enumerate firmware environment variables in this machine.");
                    GetSystemEnvironmentVariables();
                }
                else
                {
                    Console.WriteLine("[-] Due to OS functionality, this PoC does not work for OSes earlier than Win10 1809.\n");
                }
            }
            else
            {
                Console.WriteLine("[-] Failed to get OS version information.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(ntstatus, true));
            }
        }
    }
}
