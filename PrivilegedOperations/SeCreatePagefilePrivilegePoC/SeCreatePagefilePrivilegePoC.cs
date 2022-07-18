using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

namespace SeCreatePagefilePrivilegePoC
{
    class SeCreatePagefilePrivilegePoC
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
        [StructLayout(LayoutKind.Explicit)]
        struct LARGE_INTEGER
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
        struct UNICODE_STRING : IDisposable
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

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
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

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr GetModuleHandle(string ModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FreeLibrary(IntPtr hLibModule);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("ntdll.dll")]
        static extern int NtCreatePagingFile(
            in UNICODE_STRING PageFileName,
            in LARGE_INTEGER MinimumSize,
            in LARGE_INTEGER MaximumSize,
            uint Priority);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern int QueryDosDevice(
            string lpDeviceName,
            StringBuilder lpTargetPath,
            int ucchMax);

        /*
         * Win32 Consts
         */
        const int STATUS_SUCCESS = 0;

        /*
         * User defined functions
         */
        static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            var message = new StringBuilder();
            var messageSize = 255;
            ProcessModuleCollection modules;
            FormatMessageFlags messageFlag;
            IntPtr pNtdll;
            message.Capacity = messageSize;

            if (isNtStatus)
            {
                pNtdll = IntPtr.Zero;
                modules = Process.GetCurrentProcess().Modules;

                foreach (ProcessModule mod in modules)
                {
                    if (string.Compare(
                        Path.GetFileName(mod.FileName),
                        "ntdll.dll",
                        StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        pNtdll = mod.BaseAddress;
                    }
                }

                messageFlag = FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE |
                    FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }
            else
            {
                pNtdll = IntPtr.Zero;
                messageFlag = FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }

            int ret = FormatMessage(
                messageFlag,
                pNtdll,
                code,
                0,
                message,
                messageSize,
                IntPtr.Zero);

            if (ret == 0)
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


        static bool ConfigurePagefileOption()
        {
            int ntstatus;
            int error;
            UNICODE_STRING pagefilePath;
            string fileName = "pagefile.sys";
            var rootDirectory = Path.GetPathRoot(Environment.CurrentDirectory).TrimEnd('\\');
            var aliasPagefilePath = string.Format(
                "{0}\\{1}",
                Path.GetPathRoot(Environment.CurrentDirectory).TrimEnd('\\'),
                fileName);
            var minimumSize = LARGE_INTEGER.FromInt64(0x200000000L);
            var maximumSize = LARGE_INTEGER.FromInt64(0x200000000L);
            int nSizeMaxPath = 256;
            var devicePath = new StringBuilder(nSizeMaxPath);

            if (QueryDosDevice(rootDirectory, devicePath, nSizeMaxPath) == 0)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get root directory path.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }

            pagefilePath = new UNICODE_STRING(string.Format(
                "{0}\\{1}",
                devicePath.ToString(),
                fileName));

            Console.WriteLine("[>] Trying to set pagefile configuration.");
            Console.WriteLine("    |-> File Path    : {0}", aliasPagefilePath.ToString());
            Console.WriteLine("    |-> Object Path  : {0}", pagefilePath.ToString());
            Console.WriteLine("    |-> Minimum Size : {0} GB", (minimumSize.ToInt64() / (1024 * 1024 * 1024)));
            Console.WriteLine("    |-> Maximum Size : {0} GB", (maximumSize.ToInt64() / (1024 * 1024 * 1024)));

            ntstatus = NtCreatePagingFile(
                in pagefilePath,
                in minimumSize,
                in maximumSize,
                0);

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to set pagefile option.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(ntstatus, true));

                return false;
            }

            Console.WriteLine("[+] Pagefile option is set successfully.");

            return true;
        }

        static void Main()
        {
            Console.WriteLine("[*] If you have SeCreatePagefilePrivilege, you can set configuration for pagefile.");
            Console.WriteLine("[*] This PoC tries to set pagefile option to specific values.");
            ConfigurePagefileOption();
        }
    }
}
