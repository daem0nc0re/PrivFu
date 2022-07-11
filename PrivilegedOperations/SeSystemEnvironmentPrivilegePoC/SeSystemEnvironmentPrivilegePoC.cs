using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

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
        struct VARIABLE_NAME
        {
            public uint NextEntryOffset;
            Guid VendorGuid;
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


        static bool GetSystemEnvironmentVariables()
        {
            int count = 0;
            IntPtr buffer;
            IntPtr pInfo;
            IntPtr pName;
            IntPtr pValue;
            int nSizeValue;
            VARIABLE_NAME_AND_VALUE info;
            uint nBufferLength = 0;

            Console.WriteLine("[>] Trying to enumerate firmware environment variables in this machine.");

            int ntstatus = NtEnumerateSystemEnvironmentValuesEx(
                VARIABLE_INFORMATION_VALUES,
                IntPtr.Zero,
                ref nBufferLength);

            if (ntstatus != STATUS_BUFFER_TOO_SMALL)
            {
                Console.WriteLine("[-] Failed to enumerate firmware environment values.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(ntstatus, true));

                return false;
            }

            buffer = Marshal.AllocHGlobal((int)nBufferLength);
            ntstatus = NtEnumerateSystemEnvironmentValuesEx(
                VARIABLE_INFORMATION_VALUES,
                buffer,
                ref nBufferLength);

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to enumerate firmware environment values.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(ntstatus, true));
                Marshal.FreeHGlobal(buffer);

                return false;
            }

            pInfo = buffer;

            do
            {
                count++;
                info = (VARIABLE_NAME_AND_VALUE)Marshal.PtrToStructure(pInfo, typeof(VARIABLE_NAME_AND_VALUE));
                pInfo = new IntPtr(pInfo.ToInt64() + info.NextEntryOffset);
                pName = new IntPtr(pInfo.ToInt64() + Marshal.OffsetOf(typeof(VARIABLE_NAME_AND_VALUE), "Name").ToInt64());
                pValue = new IntPtr(pInfo.ToInt64() + info.ValueOffset);
                nSizeValue = (int)info.ValueLength;

                Console.WriteLine();
                Console.WriteLine("Vendor GUID : {0}", info.VendorGuid);
                Console.WriteLine("Name        : {0}", Marshal.PtrToStringUni(pName));
                Console.WriteLine("Value       :\n");
                HexDump.Dump(pValue, nSizeValue, 1);

                if (info.NextEntryOffset == 0)
                    break;
            } while (true);

            Marshal.FreeHGlobal(buffer);

            Console.WriteLine();
            Console.WriteLine("[*] Enumeration is completed.");
            Console.WriteLine("[*] {0} variables are found.\n", count);

            return true;
        }


        static void Main()
        {
            Console.WriteLine("[*] If you have SeSystemEnvironmentPrivilege, you can manipulate firmware environment variables.");
            Console.WriteLine("[*] This PoC tries to enumerate firmware environment variables in this machine.");
            GetSystemEnvironmentVariables();
        }
    }
}
