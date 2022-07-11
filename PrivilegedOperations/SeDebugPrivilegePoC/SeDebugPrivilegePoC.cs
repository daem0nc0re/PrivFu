﻿using System;
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

        /*
         * P/Invoke : Win32 APIs
         */
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

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
        static extern IntPtr OpenProcess(
            ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId);

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


        static IntPtr OpenWinlogonHandle()
        {
            int winlogon;
            int error;

            Console.WriteLine("[*] If you have SeDebugPrivilege, you can get handle to any privileged process such winlogon.exe.");

            Console.WriteLine("[>] Searching winlogon PID.");

            try
            {
                winlogon = (Process.GetProcessesByName("winlogon")[0]).Id;
            }
            catch
            {
                Console.WriteLine("[-] Failed to get process ID of winlogon.");
                return IntPtr.Zero;
            }

            Console.WriteLine("[+] PID of winlogon: {0}", winlogon);
            Console.WriteLine("[>] Trying to get handle to winlogon.");

            IntPtr hProcess = OpenProcess(
                ProcessAccessFlags.PROCESS_ALL_ACCESS,
                false,
                winlogon);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get a winlogon handle.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));
                return IntPtr.Zero;
            }

            return hProcess;
        }


        static void Main()
        {
            IntPtr hProcess = OpenWinlogonHandle();

            if (hProcess != IntPtr.Zero)
            {
                Console.WriteLine("[+] Got handle to winlogon with PROCESS_ALL_ACCESS (hProcess = 0x{0}).", hProcess.ToString("X"));
                Console.WriteLine("\n[*] To close the handle and exit this program, hit [ENTER] key.");
                Console.ReadLine();

                CloseHandle(hProcess);
            }
        }
    }
}
