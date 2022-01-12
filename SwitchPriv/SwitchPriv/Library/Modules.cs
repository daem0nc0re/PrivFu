using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using SwitchPriv.Interop;

namespace SwitchPriv.Library
{
    public class Modules
    {
        public static bool DisableAllPrivileges(int pid)
        {
            int error;
            IntPtr hProcess;

            if (pid == 0)
                pid = Helpers.GetParentProcessId(new IntPtr(-1));

            if (pid == 0)
                return false;

            Console.WriteLine("[>] Trying to disable all token privileges.");
            Console.WriteLine("    |-> Target PID : {0}", pid);

            hProcess = Win32Api.OpenProcess(
                    (uint)Win32Const.ProcessAccessFlags.PROCESS_QUERY_INFORMATION,
                    false,
                    pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error));
                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                (uint)(Win32Const.TokenAccessFlags.TOKEN_QUERY | Win32Const.TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES),
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error));
                Win32Api.CloseHandle(hProcess);
                return false;
            }

            Dictionary<string, bool> privStatus = Helpers.GetPrivilegeStatus(hToken);

            foreach (var status in privStatus)
            {
                if (status.Value)
                    Helpers.DisableSinglePrivilege(hToken, status.Key);
            }

            Console.WriteLine("[*] Done.");

            Win32Api.CloseHandle(hToken);
            Win32Api.CloseHandle(hProcess);

            return true;
        }

        public static bool DisableTokenPrivilege(int pid, string privilegeName)
        {
            int error;
            IntPtr hProcess;

            if (pid == 0)
                pid = Helpers.GetParentProcessId(new IntPtr(-1));

            if (pid == 0)
                return false;

            Console.WriteLine("[>] Trying to disable {0}.", privilegeName);
            Console.WriteLine("    |-> Target PID : {0}", pid);

            hProcess = Win32Api.OpenProcess(
                    (uint)Win32Const.ProcessAccessFlags.PROCESS_QUERY_INFORMATION,
                    false,
                    pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error));
                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                (uint)(Win32Const.TokenAccessFlags.TOKEN_QUERY | Win32Const.TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES),
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error));
                Win32Api.CloseHandle(hProcess);
                return false;
            }

            bool status = Helpers.DisableSinglePrivilege(hToken, privilegeName);

            if (status && Marshal.GetLastWin32Error() == 0) // ERROR_SUCCESS = 0
            {
                Console.WriteLine("[+] {0} is disabled successfully.", privilegeName);
            }
            else if (status && Marshal.GetLastWin32Error() == 1300) // ERROR_NOT_ALL_ASSIGNED = 1300
            {
                Console.WriteLine("[-] {0} is not available for the target process.", privilegeName);
            }
            else
            {
                Console.WriteLine("[-] Failed to disable {0}.", privilegeName);
            }

            Win32Api.CloseHandle(hToken);
            Win32Api.CloseHandle(hProcess);

            return true;
        }

        public static bool EnableAllPrivileges(int pid)
        {
            int error;
            IntPtr hProcess;

            if (pid == 0)
                pid = Helpers.GetParentProcessId(new IntPtr(-1));

            if (pid == 0)
                return false;

            Console.WriteLine("[>] Trying to enable all token privileges.");
            Console.WriteLine("    |-> Target PID : {0}", pid);

            hProcess = Win32Api.OpenProcess(
                    (uint)Win32Const.ProcessAccessFlags.PROCESS_QUERY_INFORMATION,
                    false,
                    pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error));
                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                (uint)(Win32Const.TokenAccessFlags.TOKEN_QUERY | Win32Const.TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES),
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error));
                Win32Api.CloseHandle(hProcess);
                return false;
            }

            Dictionary<string, bool> privStatus = Helpers.GetPrivilegeStatus(hToken);

            foreach (var status in privStatus)
            {
                if (!status.Value)
                    Helpers.EnableSinglePrivilege(hToken, status.Key);
            }

            Console.WriteLine("[*] Done.");

            Win32Api.CloseHandle(hToken);
            Win32Api.CloseHandle(hProcess);

            return true;
        }

        public static bool EnableTokenPrivilege(int pid, string privilegeName)
        {
            int error;
            IntPtr hProcess;

            if (pid == 0)
                pid = Helpers.GetParentProcessId(new IntPtr(-1));

            if (pid == 0)
                return false;

            Console.WriteLine("[>] Trying to enable {0}.", privilegeName);
            Console.WriteLine("    |-> Target PID : {0}", pid);

            hProcess = Win32Api.OpenProcess(
                    (uint)Win32Const.ProcessAccessFlags.PROCESS_QUERY_INFORMATION,
                    false,
                    pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error));
                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                (uint)(Win32Const.TokenAccessFlags.TOKEN_QUERY | Win32Const.TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES),
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error));
                Win32Api.CloseHandle(hProcess);
                return false;
            }

            bool status = Helpers.EnableSinglePrivilege(hToken, privilegeName);

            if (status && Marshal.GetLastWin32Error() == 0) // ERROR_SUCCESS = 0
            {
                Console.WriteLine("[+] {0} is enabled successfully.", privilegeName);
            }
            else if (status && Marshal.GetLastWin32Error() == 1300) // ERROR_NOT_ALL_ASSIGNED = 1300
            {
                Console.WriteLine("[-] {0} is not available for the target process.", privilegeName);
            }
            else
            {
                Console.WriteLine("[-] Failed to enable {0}.", privilegeName);
            }

            Win32Api.CloseHandle(hToken);
            Win32Api.CloseHandle(hProcess);

            return true;
        }
    }
}
