using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using SwitchPriv.Interop;

namespace SwitchPriv.Library
{
    class Modules
    {
        public static bool DisableAllPrivileges(int pid, bool asSystem)
        {
            int error;
            IntPtr hProcess;

            if (pid == 0)
                pid = Utilities.GetParentProcessId(new IntPtr(-1));

            if (pid == 0)
                return false;

            Console.WriteLine();
            Console.WriteLine("[>] Trying to disable all token privileges.");
            Console.WriteLine("    |-> Target PID   : {0}", pid);

            try
            {
                Console.WriteLine("    |-> Process Name : {0}", (Process.GetProcessById(pid)).ProcessName);
            }
            catch
            {
                Console.WriteLine("\n[-] There is no target process, or integrity level is insufficient.\n");

                return false;
            }

            if (asSystem)
                if (!GetSystem())
                    return false;

            hProcess = Win32Api.OpenProcess(
                Win32Const.ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                Win32Const.TokenAccessFlags.TOKEN_QUERY | Win32Const.TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hProcess);

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            Dictionary<Win32Struct.LUID, uint> privs = Utilities.GetAvailablePrivileges(hToken);
            bool isEnabled;

            foreach (var priv in privs)
            {
                isEnabled = ((priv.Value & (uint)Win32Const.PrivilegeAttributeFlags.SE_PRIVILEGE_ENABLED) != 0);

                if (isEnabled)
                    if (Utilities.DisableSinglePrivilege(hToken, priv.Key))
                        Console.WriteLine("[+] {0} is disabled successfully.", Helpers.GetPrivilegeName(priv.Key));
            }

            Console.WriteLine("[*] Done.\n");

            Win32Api.CloseHandle(hToken);
            Win32Api.CloseHandle(hProcess);

            if (asSystem)
                Win32Api.RevertToSelf();

            return true;
        }


        public static bool DisableTokenPrivilege(
            int pid,
            string privilegeName,
            bool asSystem)
        {
            int error;
            IntPtr hProcess;

            if (!Helpers.GetPrivilegeLuid(privilegeName, out Win32Struct.LUID priv))
                return false;

            if (pid == 0)
                pid = Utilities.GetParentProcessId(new IntPtr(-1));

            if (pid == 0)
                return false;

            Console.WriteLine();
            Console.WriteLine("[>] Trying to disable {0}.", privilegeName);
            Console.WriteLine("    |-> Target PID   : {0}", pid);

            try
            {
                Console.WriteLine("    |-> Process Name : {0}", (Process.GetProcessById(pid)).ProcessName);
            }
            catch
            {
                Console.WriteLine("\n[-] There is no target process, or integrity level is insufficient.\n");

                return false;
            }

            if (asSystem)
                if (!GetSystem())
                    return false;


            hProcess = Win32Api.OpenProcess(
                Win32Const.ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                Win32Const.TokenAccessFlags.TOKEN_QUERY | Win32Const.TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hProcess);

                if (asSystem)
                    Win32Api.RevertToSelf();

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

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            if (!isEnabled)
            {
                Console.WriteLine("[-] {0} is already disabled.\n", privilegeName);
                Win32Api.CloseHandle(hToken);
                Win32Api.CloseHandle(hProcess);

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            if (Utilities.DisableSinglePrivilege(hToken, priv))
                Console.WriteLine("[+] {0} is disabled successfully.\n", privilegeName);

            Win32Api.CloseHandle(hToken);
            Win32Api.CloseHandle(hProcess);

            if (asSystem)
                Win32Api.RevertToSelf();

            return true;
        }


        public static bool EnableAllPrivileges(int pid, bool asSystem)
        {
            int error;
            IntPtr hProcess;

            if (pid == 0)
                pid = Utilities.GetParentProcessId(new IntPtr(-1));

            if (pid == 0)
                return false;

            Console.WriteLine();
            Console.WriteLine("[>] Trying to enable all token privileges.");
            Console.WriteLine("    |-> Target PID   : {0}", pid);

            try
            {
                Console.WriteLine("    |-> Process Name : {0}", (Process.GetProcessById(pid)).ProcessName);
            }
            catch
            {
                Console.WriteLine("\n[-] There is no target process, or integrity level is insufficient.\n");

                return false;
            }

            if (asSystem)
                if (!GetSystem())
                    return false;


            hProcess = Win32Api.OpenProcess(
                    Win32Const.ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                    false,
                    pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                Win32Const.TokenAccessFlags.TOKEN_QUERY | Win32Const.TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hProcess);

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            Dictionary<Win32Struct.LUID, uint> privs = Utilities.GetAvailablePrivileges(hToken);
            bool isEnabled;

            foreach (var priv in privs)
            {
                isEnabled = ((priv.Value & (uint)Win32Const.PrivilegeAttributeFlags.SE_PRIVILEGE_ENABLED) != 0);

                if (!isEnabled)
                    if (Utilities.EnableSinglePrivilege(hToken, priv.Key))
                        Console.WriteLine("[+] {0} is enabled successfully.", Helpers.GetPrivilegeName(priv.Key));
            }

            Console.WriteLine("[*] Done.\n");

            Win32Api.CloseHandle(hToken);
            Win32Api.CloseHandle(hProcess);

            if (asSystem)
                Win32Api.RevertToSelf();

            return true;
        }


        public static bool EnableTokenPrivilege(
            int pid,
            string privilegeName,
            bool asSystem)
        {
            int error;
            IntPtr hProcess;

            if (!Helpers.GetPrivilegeLuid(privilegeName, out Win32Struct.LUID priv))
                return false;

            if (pid == 0)
                pid = Utilities.GetParentProcessId(new IntPtr(-1));

            if (pid == 0)
                return false;

            Console.WriteLine();
            Console.WriteLine("[>] Trying to enable {0}.", privilegeName);
            Console.WriteLine("    |-> Target PID   : {0}", pid);

            try
            {
                Console.WriteLine("    |-> Process Name : {0}", (Process.GetProcessById(pid)).ProcessName);
            }
            catch
            {
                Console.WriteLine("\n[-] There is no target process, or integrity level is insufficient.\n");

                return false;
            }

            if (asSystem)
                if (!GetSystem())
                    return false;


            hProcess = Win32Api.OpenProcess(
                Win32Const.ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                Win32Const.TokenAccessFlags.TOKEN_QUERY | Win32Const.TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hProcess);

                if (asSystem)
                    Win32Api.RevertToSelf();

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

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            if (isEnabled)
            {
                Console.WriteLine("[-] {0} is already enabled.\n", privilegeName);
                Win32Api.CloseHandle(hToken);
                Win32Api.CloseHandle(hProcess);

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            if (Utilities.EnableSinglePrivilege(hToken, priv))
                Console.WriteLine("[+] {0} is enabled successfully.\n", privilegeName);

            Win32Api.CloseHandle(hToken);
            Win32Api.CloseHandle(hProcess);

            if (asSystem)
                Win32Api.RevertToSelf();

            return true;
        }


        public static bool FindPrivilegedProcess(
            string targetPrivilege,
            bool asSystem)
        {
            IntPtr hProcess;
            string privilege;
            Dictionary<Win32Struct.LUID, uint> privs;
            int nCountFound = 0;
            var processList = Process.GetProcesses();
            var deniedProcess = new Dictionary<int, string>();

            Console.WriteLine();
            Console.WriteLine("[>] Searching process have {0}.", targetPrivilege);

            if (asSystem)
                if (!GetSystem())
                    return false;

            foreach (var proc in processList)
            {
                hProcess = Win32Api.OpenProcess(
                    Win32Const.ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                    false,
                    proc.Id);

                if (hProcess == IntPtr.Zero)
                {
                    deniedProcess.Add(proc.Id, proc.ProcessName);
                    continue;
                }

                if (!Win32Api.OpenProcessToken(
                    hProcess,
                    Win32Const.TokenAccessFlags.TOKEN_QUERY,
                    out IntPtr hToken))
                {
                    deniedProcess.Add(proc.Id, proc.ProcessName);
                    Win32Api.CloseHandle(hProcess);
                    continue;
                }

                privs = Utilities.GetAvailablePrivileges(hToken);
                Win32Api.CloseHandle(hToken);
                Win32Api.CloseHandle(hProcess);

                foreach (var luid in privs.Keys)
                {
                    privilege = Helpers.GetPrivilegeName(luid);

                    if (string.Compare(
                        privilege,
                        targetPrivilege,
                        StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        if (nCountFound == 0)
                            Console.WriteLine("[+] Following Processes have {0}.", targetPrivilege);

                        Console.WriteLine("    |-> {0} (PID : {1})", proc.ProcessName, proc.Id);
                        nCountFound++;
                        break;
                    }
                }
            }

            if (asSystem)
                Win32Api.RevertToSelf();

            if (nCountFound == 0)
                Console.WriteLine("[-] No process has {0}.", targetPrivilege);
            else
                Console.WriteLine("[+] {0} process have {1}.", nCountFound, targetPrivilege);

            if (deniedProcess.Count > 0)
            {
                Console.WriteLine("[*] Access is denied by following {0} process.", deniedProcess.Count);

                foreach (var denied in deniedProcess)
                {
                    Console.WriteLine("    |-> {0} (PID : {1})", denied.Value, denied.Key);
                }
            }

            Console.WriteLine("[*] Done.\n");

            return true;
        }


        public static bool GetPrivileges(int pid, bool asSystem)
        {
            int error;
            IntPtr hProcess;

            if (pid == 0)
                pid = Utilities.GetParentProcessId(new IntPtr(-1));

            if (pid == 0)
                return false;

            Console.WriteLine();
            Console.WriteLine("[>] Trying to get available token privilege(s) for the target process.");
            Console.WriteLine("    |-> Target PID   : {0}", pid);

            try
            {
                Console.WriteLine("    |-> Process Name : {0}", (Process.GetProcessById(pid)).ProcessName);
            }
            catch
            {
                Console.WriteLine("\n[-] There is no target process, or integrity level is insufficient.\n");

                return false;
            }

            if (asSystem)
                if (!GetSystem())
                    return false;

            hProcess = Win32Api.OpenProcess(
                Win32Const.ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                Win32Const.TokenAccessFlags.TOKEN_QUERY,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hProcess);

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            Dictionary<Win32Struct.LUID, uint> privs = Utilities.GetAvailablePrivileges(hToken);
            bool isEnabled;
            string privilegeName;

            Console.WriteLine();

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

            Console.WriteLine("\n[*] Integrity Level : {0}\n", Utilities.GetIntegrityLevel(hToken));

            Win32Api.CloseHandle(hToken);
            Win32Api.CloseHandle(hProcess);

            if (asSystem)
                Win32Api.RevertToSelf();

            return true;
        }


        private static bool GetSystem()
        {
            Console.WriteLine("[>] Trying to get SYSTEM.");

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            var privs = new string[] {
                Win32Const.SE_DEBUG_NAME,
                Win32Const.SE_IMPERSONATE_NAME
            };

            if (!Utilities.EnableMultiplePrivileges(hCurrentToken, privs))
            {
                Console.WriteLine("[!] Should be run with administrative privilege.");
                Win32Api.CloseHandle(hCurrentToken);

                return false;
            }

            return Utilities.ImpersonateAsSmss(new string[] { });
        }


        public static bool RemoveAllPrivileges(int pid, bool asSystem)
        {
            int error;
            IntPtr hProcess;

            if (pid == 0)
                pid = Utilities.GetParentProcessId(new IntPtr(-1));

            if (pid == 0)
                return false;

            Console.WriteLine();
            Console.WriteLine("[>] Trying to remove all token privileges.");
            Console.WriteLine("    |-> Target PID   : {0}", pid);

            try
            {
                Console.WriteLine("    |-> Process Name : {0}", (Process.GetProcessById(pid)).ProcessName);
            }
            catch
            {
                Console.WriteLine("\n[-] There is no target process, or integrity level is insufficient.\n");

                return false;
            }

            if (asSystem)
                if (!GetSystem())
                    return false;


            hProcess = Win32Api.OpenProcess(
                    Win32Const.ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                    false,
                    pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                Win32Const.TokenAccessFlags.TOKEN_QUERY | Win32Const.TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hProcess);

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            Dictionary<Win32Struct.LUID, uint> privs = Utilities.GetAvailablePrivileges(hToken);
            
            foreach (var priv in privs)
            {
                if (Utilities.RemoveSinglePrivilege(hToken, priv.Key))
                    Console.WriteLine("[+] {0} is removed successfully.", Helpers.GetPrivilegeName(priv.Key));
            }

            Console.WriteLine("[*] Done.\n");

            Win32Api.CloseHandle(hToken);
            Win32Api.CloseHandle(hProcess);

            if (asSystem)
                Win32Api.RevertToSelf();

            return true;
        }


        public static bool RemoveTokenPrivilege(
            int pid,
            string privilegeName,
            bool asSystem)
        {
            int error;
            IntPtr hProcess;

            if (!Helpers.GetPrivilegeLuid(privilegeName, out Win32Struct.LUID priv))
                return false;

            if (pid == 0)
                pid = Utilities.GetParentProcessId(new IntPtr(-1));

            if (pid == 0)
                return false;

            Console.WriteLine();
            Console.WriteLine("[>] Trying to remove {0}.", privilegeName);
            Console.WriteLine("    |-> Target PID   : {0}", pid);

            try
            {
                Console.WriteLine("    |-> Process Name : {0}", (Process.GetProcessById(pid)).ProcessName);
            }
            catch
            {
                Console.WriteLine("\n[-] There is no target process, or integrity level is insufficient.\n");

                return false;
            }

            if (asSystem)
                if (!GetSystem())
                    return false;


            hProcess = Win32Api.OpenProcess(
                Win32Const.ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                Win32Const.TokenAccessFlags.TOKEN_QUERY | Win32Const.TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hProcess);

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            Dictionary<Win32Struct.LUID, uint> privs = Utilities.GetAvailablePrivileges(hToken);
            bool isAvailable = false;

            foreach (var luidAndAttr in privs)
            {
                if (luidAndAttr.Key.LowPart == priv.LowPart && luidAndAttr.Key.HighPart == priv.HighPart)
                {
                    isAvailable = true;

                    break;
                }
            }

            if (!isAvailable)
            {
                Console.WriteLine("[-] {0} is already removed.\n", privilegeName);
                Win32Api.CloseHandle(hToken);
                Win32Api.CloseHandle(hProcess);

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            if (Utilities.RemoveSinglePrivilege(hToken, priv))
                Console.WriteLine("[+] {0} is removed successfully.\n", privilegeName);

            Win32Api.CloseHandle(hToken);
            Win32Api.CloseHandle(hProcess);

            if (asSystem)
                Win32Api.RevertToSelf();

            return true;
        }


        public static bool SetIntegrityLevel(
            int pid,
            int integrityLevelIndex,
            bool asSystem)
        {
            int error;
            IntPtr hProcess;
            string mandatoryLevelSid = Helpers.ConvertIndexToMandatoryLevelSid(integrityLevelIndex);

            if (pid == 0)
                pid = Utilities.GetParentProcessId(new IntPtr(-1));

            if (pid == 0)
                return false;

            Console.WriteLine();
            Console.WriteLine("[>] Trying to set integrity level.");
            Console.WriteLine("    |-> Target PID   : {0}", pid);

            try
            {
                Console.WriteLine("    |-> Process Name : {0}", (Process.GetProcessById(pid)).ProcessName);
            }
            catch
            {
                Console.WriteLine("\n[-] There is no target process, or integrity level is insufficient.\n");

                return false;
            }

            if (string.IsNullOrEmpty(mandatoryLevelSid))
            {
                Console.WriteLine("[-] Failed to resolve integrity level.");

                return false;
            }

            if (asSystem)
                if(!GetSystem())
                    return false;

            hProcess = Win32Api.OpenProcess(
                Win32Const.ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                Win32Const.TokenAccessFlags.MAXIMUM_ALLOWED,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hProcess);

                if (asSystem)
                    Win32Api.RevertToSelf();

                return false;
            }

            Utilities.SetMandatoryLevel(hToken, mandatoryLevelSid);

            Win32Api.CloseHandle(hToken);
            Win32Api.CloseHandle(hProcess);

            if (asSystem)
                Win32Api.RevertToSelf();

            return true;
        }
    }
}