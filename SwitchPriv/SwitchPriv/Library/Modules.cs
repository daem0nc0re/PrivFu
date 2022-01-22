using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using SwitchPriv.Interop;

namespace SwitchPriv.Library
{
    class Modules
    {
        public static bool DisableAllPrivileges(int pid)
        {
            int error;
            IntPtr hProcess;

            if (pid == 0)
                pid = Utilities.GetParentProcessId(new IntPtr(-1));

            if (pid == 0)
                return false;

            Console.WriteLine("\n[>] Trying to disable all token privileges.");
            Console.WriteLine("    |-> Target PID   : {0}", pid);
            try
            {
                Console.WriteLine("    |-> Process Name : {0}\n", (Process.GetProcessById(pid)).ProcessName);
            }
            catch
            {
                Console.WriteLine("[-] There is no target process.\n");
                return false;
            }

            hProcess = Win32Api.OpenProcess(
                (uint)Win32Const.ProcessAccessFlags.PROCESS_QUERY_INFORMATION,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                (uint)(Win32Const.TokenAccessFlags.TOKEN_QUERY | Win32Const.TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES),
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hProcess);
                return false;
            }

            Dictionary<Win32Struct.LUID, uint> privs = Utilities.GetAvailablePrivileges(hToken);
            bool isEnabled;
            bool status;

            foreach (var priv in privs)
            {
                isEnabled = ((priv.Value & (uint)Win32Const.PrivilegeAttributeFlags.SE_PRIVILEGE_ENABLED) != 0);

                if (isEnabled)
                {
                    status = Utilities.DisableSinglePrivilege(hToken, priv.Key);
                    if (status)
                    {
                        Console.WriteLine("[+] {0} is disabled successfully.", Helpers.GetPrivilegeName(priv.Key));
                    }
                }
            }

            Console.WriteLine("[*] Done.\n");

            Win32Api.CloseHandle(hToken);
            Win32Api.CloseHandle(hProcess);

            return true;
        }


        public static bool DisableTokenPrivilege(int pid, string privilegeName)
        {
            int error;
            IntPtr hProcess;

            if (!Helpers.GetPrivilegeLuid(privilegeName, out Win32Struct.LUID priv))
                return false;

            if (pid == 0)
                pid = Utilities.GetParentProcessId(new IntPtr(-1));

            if (pid == 0)
                return false;

            Console.WriteLine("\n[>] Trying to disable {0}.", privilegeName);
            Console.WriteLine("    |-> Target PID   : {0}", pid);
            try
            {
                Console.WriteLine("    |-> Process Name : {0}\n", (Process.GetProcessById(pid)).ProcessName);
            }
            catch
            {
                Console.WriteLine("\n[-] There is no target process.\n");
                return false;
            }

            hProcess = Win32Api.OpenProcess(
                (uint)Win32Const.ProcessAccessFlags.PROCESS_QUERY_INFORMATION,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                (uint)(Win32Const.TokenAccessFlags.TOKEN_QUERY | Win32Const.TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES),
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hProcess);
                return false;
            }

            Dictionary<Win32Struct.LUID, uint> privs = Utilities.GetAvailablePrivileges(hToken);
            bool isAvailable = false;
            bool isEnabled = false;

            foreach (var luidAndAttr in privs)
            {
                if (luidAndAttr.Key.LowPart == priv.LowPart && luidAndAttr.Key.HighPart == priv.HighPart)
                {
                    isAvailable = true;
                    isEnabled = ((luidAndAttr.Value & (uint)Win32Const.PrivilegeAttributeFlags.SE_PRIVILEGE_ENABLED) != 0);
                    break;
                }
            }

            if (!isAvailable)
            {
                Console.WriteLine("[-] {0} is not available for the target process.\n", privilegeName);
                Win32Api.CloseHandle(hToken);
                Win32Api.CloseHandle(hProcess);
                return false;
            }

            if (!isEnabled)
            {
                Console.WriteLine("[-] {0} is already disabled.\n", privilegeName);
                Win32Api.CloseHandle(hToken);
                Win32Api.CloseHandle(hProcess);
                return false;
            }

            bool status = Utilities.DisableSinglePrivilege(hToken, priv);

            if (status)
            {
                Console.WriteLine("[+] {0} is disabled successfully.\n", privilegeName);
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
                pid = Utilities.GetParentProcessId(new IntPtr(-1));

            if (pid == 0)
                return false;

            Console.WriteLine("\n[>] Trying to enable all token privileges.");
            Console.WriteLine("    |-> Target PID   : {0}", pid);
            try
            {
                Console.WriteLine("    |-> Process Name : {0}\n", (Process.GetProcessById(pid)).ProcessName);
            }
            catch
            {
                Console.WriteLine("\n[-] There is no target process.\n");
                return false;
            }

            hProcess = Win32Api.OpenProcess(
                    (uint)Win32Const.ProcessAccessFlags.PROCESS_QUERY_INFORMATION,
                    false,
                    pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                (uint)(Win32Const.TokenAccessFlags.TOKEN_QUERY | Win32Const.TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES),
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hProcess);
                return false;
            }

            Dictionary<Win32Struct.LUID, uint> privs = Utilities.GetAvailablePrivileges(hToken);
            bool isEnabled;
            bool status;

            foreach (var priv in privs)
            {
                isEnabled = ((priv.Value & (uint)Win32Const.PrivilegeAttributeFlags.SE_PRIVILEGE_ENABLED) != 0);

                if (!isEnabled)
                {
                    status = Utilities.EnableSinglePrivilege(hToken, priv.Key);
                    if (status)
                    {
                        Console.WriteLine("[+] {0} is enabled successfully.", Helpers.GetPrivilegeName(priv.Key));
                    }
                }
            }

            Console.WriteLine("[*] Done.\n");

            Win32Api.CloseHandle(hToken);
            Win32Api.CloseHandle(hProcess);

            return true;
        }


        public static bool EnableTokenPrivilege(int pid, string privilegeName)
        {
            int error;
            IntPtr hProcess;

            if (!Helpers.GetPrivilegeLuid(privilegeName, out Win32Struct.LUID priv))
                return false;

            if (pid == 0)
                pid = Utilities.GetParentProcessId(new IntPtr(-1));

            if (pid == 0)
                return false;

            Console.WriteLine("\n[>] Trying to enable {0}.", privilegeName);
            Console.WriteLine("    |-> Target PID   : {0}", pid);
            try
            {
                Console.WriteLine("    |-> Process Name : {0}\n", (Process.GetProcessById(pid)).ProcessName);
            }
            catch
            {
                Console.WriteLine("\n[-] There is no target process.\n");
                return false;
            }

            hProcess = Win32Api.OpenProcess(
                (uint)Win32Const.ProcessAccessFlags.PROCESS_QUERY_INFORMATION,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                (uint)(Win32Const.TokenAccessFlags.TOKEN_QUERY | Win32Const.TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES),
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hProcess);
                return false;
            }

            Dictionary<Win32Struct.LUID, uint> privs = Utilities.GetAvailablePrivileges(hToken);
            bool isAvailable = false;
            bool isEnabled = false;

            foreach (var luidAndAttr in privs)
            {
                if (luidAndAttr.Key.LowPart == priv.LowPart && luidAndAttr.Key.HighPart == priv.HighPart)
                {
                    isAvailable = true;
                    isEnabled = ((luidAndAttr.Value & (uint)Win32Const.PrivilegeAttributeFlags.SE_PRIVILEGE_ENABLED) != 0);
                    break;
                }
            }

            if (!isAvailable)
            {
                Console.WriteLine("[-] {0} is not available for the target process.\n", privilegeName);
                Win32Api.CloseHandle(hToken);
                Win32Api.CloseHandle(hProcess);
                return false;
            }

            if (isEnabled)
            {
                Console.WriteLine("[-] {0} is already enabled.\n", privilegeName);
                Win32Api.CloseHandle(hToken);
                Win32Api.CloseHandle(hProcess);
                return false;
            }

            bool status = Utilities.EnableSinglePrivilege(hToken, priv);

            if (status)
            {
                Console.WriteLine("[+] {0} is enabled successfully.\n", privilegeName);
            }

            Win32Api.CloseHandle(hToken);
            Win32Api.CloseHandle(hProcess);

            return true;
        }


        public static bool GetPrivileges(int pid)
        {
            int error;
            IntPtr hProcess;

            if (pid == 0)
                pid = Utilities.GetParentProcessId(new IntPtr(-1));

            if (pid == 0)
                return false;

            Console.WriteLine("\n[>] Trying to get available token privilege(s) for the target process.");
            Console.WriteLine("    |-> Target PID   : {0}", pid);
            try
            {
                Console.WriteLine("    |-> Process Name : {0}\n", (Process.GetProcessById(pid)).ProcessName);
            }
            catch
            {
                Console.WriteLine("\n[-] There is no target process.\n");
                return false;
            }

            hProcess = Win32Api.OpenProcess(
                (uint)Win32Const.ProcessAccessFlags.PROCESS_QUERY_INFORMATION,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                (uint)Win32Const.TokenAccessFlags.TOKEN_QUERY,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hProcess);
                return false;
            }

            Dictionary<Win32Struct.LUID, uint> privs = Utilities.GetAvailablePrivileges(hToken);
            bool isEnabled;
            string privilegeName;

            if (privs.Count > 0)
            {
                Console.WriteLine("Privilege Name                             State");
                Console.WriteLine("========================================== ========");
            }
            else
            {
                Console.WriteLine("[*] No available token privilege.");
            }

            foreach (var priv in privs)
            {
                isEnabled = ((priv.Value & (uint)Win32Const.PrivilegeAttributeFlags.SE_PRIVILEGE_ENABLED) != 0);
                privilegeName = Helpers.GetPrivilegeName(priv.Key);
                Console.WriteLine("{0,-42} {1}", privilegeName, isEnabled ? "Enabled" : "Disabled");
            }

            Console.WriteLine();

            Win32Api.CloseHandle(hToken);
            Win32Api.CloseHandle(hProcess);

            return true;
        }
    }
}