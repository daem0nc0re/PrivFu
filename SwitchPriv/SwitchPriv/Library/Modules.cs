using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using SwitchPriv.Interop;

namespace SwitchPriv.Library
{
    internal class Modules
    {
        public static bool DisableAllPrivileges(int pid, bool asSystem)
        {
            int error;
            IntPtr hProcess;

            if (pid == 0)
                pid = Helpers.GetParentProcessId();

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

            hProcess = NativeMethods.OpenProcess(
                ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                if (asSystem)
                    NativeMethods.RevertToSelf();

                return false;
            }

            if (!NativeMethods.OpenProcessToken(
                hProcess,
                TokenAccessFlags.TOKEN_QUERY | TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                NativeMethods.CloseHandle(hProcess);

                if (asSystem)
                    NativeMethods.RevertToSelf();

                return false;
            }

            bool isEnabled;
            Helpers.GetTokenPrivileges(hToken, out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> privs);

            foreach (var priv in privs)
            {
                isEnabled = ((priv.Value & SE_PRIVILEGE_ATTRIBUTES.ENABLED) != 0);

                if (isEnabled)
                    if (Utilities.DisableSinglePrivilege(hToken, priv.Key))
                        Console.WriteLine("[+] {0} is disabled successfully.", priv.Key);
            }

            Console.WriteLine("[*] Done.\n");

            NativeMethods.CloseHandle(hToken);
            NativeMethods.CloseHandle(hProcess);

            if (asSystem)
                NativeMethods.RevertToSelf();

            return true;
        }


        public static bool DisableTokenPrivilege(int pid, string privilegeName, bool asSystem)
        {
            int error;
            IntPtr hProcess;

            if (pid == 0)
                pid = Helpers.GetParentProcessId();

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

            hProcess = NativeMethods.OpenProcess(
                ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                if (asSystem)
                    NativeMethods.RevertToSelf();

                return false;
            }

            if (!NativeMethods.OpenProcessToken(
                hProcess,
                TokenAccessFlags.TOKEN_QUERY | TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                NativeMethods.CloseHandle(hProcess);

                if (asSystem)
                    NativeMethods.RevertToSelf();

                return false;
            }

            bool isAvailable = false;
            bool isEnabled = false;
            Helpers.GetTokenPrivileges(hToken, out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> privs);

            foreach (var priv in privs)
            {
                if (Helpers.CompareIgnoreCase(priv.Key, privilegeName))
                {
                    isAvailable = true;
                    isEnabled = ((priv.Value & SE_PRIVILEGE_ATTRIBUTES.ENABLED) != 0);
                    break;
                }
            }

            if (!isAvailable)
            {
                Console.WriteLine("[-] {0} is not available for the target process.\n", privilegeName);
                NativeMethods.CloseHandle(hToken);
                NativeMethods.CloseHandle(hProcess);

                if (asSystem)
                    NativeMethods.RevertToSelf();

                return false;
            }

            if (!isEnabled)
            {
                Console.WriteLine("[-] {0} is already disabled.\n", privilegeName);
                NativeMethods.CloseHandle(hToken);
                NativeMethods.CloseHandle(hProcess);

                if (asSystem)
                    NativeMethods.RevertToSelf();

                return false;
            }

            if (Utilities.DisableSinglePrivilege(hToken, privilegeName))
                Console.WriteLine("[+] {0} is disabled successfully.\n", privilegeName);

            NativeMethods.CloseHandle(hToken);
            NativeMethods.CloseHandle(hProcess);

            if (asSystem)
                NativeMethods.RevertToSelf();

            return true;
        }


        public static bool EnableAllPrivileges(int pid, bool asSystem)
        {
            var status = false;

            if (pid == 0)
            {
                pid = Helpers.GetParentProcessId();

                if (pid == 0)
                {
                    Console.WriteLine("[-] Failed to specify the target PID.");
                    return status;
                }
            }

            do
            {
                int error;
                IntPtr hProcess;
                var privsToEnable = new List<string>();

                try
                {
                    Console.WriteLine("[>] Trying to enable all token privileges.");
                    Console.WriteLine("    [*] Target PID   : {0}", pid);
                    Console.WriteLine("    [*] Process Name : {0}", (Process.GetProcessById(pid)).ProcessName);
                }
                catch
                {
                    Console.WriteLine("[-] Failed to find the specified PID.");
                    break;
                }

                if (asSystem)
                {
                    asSystem = GetSystem();

                    if (!asSystem)
                        break;
                }

                hProcess = NativeMethods.OpenProcess(
                    ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                    false,
                    pid);

                if (hProcess == IntPtr.Zero)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to open the target process (PID = {0}).", pid);
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }

                status = NativeMethods.OpenProcessToken(
                    hProcess,
                    TokenAccessFlags.TOKEN_QUERY | TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES,
                    out IntPtr hToken);
                NativeMethods.CloseHandle(hProcess);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to get a token from the target process (PID = {0}).", pid);
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }

                Helpers.GetTokenPrivileges(hToken, out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                foreach (var priv in availablePrivs)
                {
                    if ((priv.Value & SE_PRIVILEGE_ATTRIBUTES.ENABLED) == 0)
                        privsToEnable.Add(priv.Key);
                }

                if (privsToEnable.Count == 0)
                {
                    Console.WriteLine("[*] All token privileges are already enabled.");
                    break;
                }

                status = Utilities.EnableTokenPrivileges(
                    hToken,
                    privsToEnable,
                    out Dictionary<string, bool> adjustedPrivs);
                NativeMethods.CloseHandle(hToken);

                foreach (var priv in adjustedPrivs)
                {
                    if (priv.Value)
                        Console.WriteLine("[+] {0} is enabled successfully.", priv.Key);
                    else
                        Console.WriteLine("[-] Failed to enable {0}.", priv.Key);
                }
            } while (false);

            if (asSystem)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool EnableTokenPrivilege(int pid, string privilegeName, bool asSystem)
        {
            var status = false;

            if (pid == 0)
            {
                pid = Helpers.GetParentProcessId();

                if (pid == 0)
                {
                    Console.WriteLine("[-] Failed to specify the target PID.");
                    return status;
                }
            }

            do
            {
                int error;
                IntPtr hProcess;
                var isAvailable = false;

                try
                {
                    Console.WriteLine("[>] Trying to enable {0}.", privilegeName);
                    Console.WriteLine("    [*] Target PID   : {0}", pid);
                    Console.WriteLine("    [*] Process Name : {0}", (Process.GetProcessById(pid)).ProcessName);
                }
                catch
                {
                    Console.WriteLine("[-] Failed to find the specified PID.");
                    break;
                }

                if (asSystem)
                {
                    asSystem = GetSystem();

                    if (!asSystem)
                        break;
                }

                hProcess = NativeMethods.OpenProcess(
                    ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                    false,
                    pid);

                if (hProcess == IntPtr.Zero)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to open the target process (PID = {0}).", pid);
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }

                status = NativeMethods.OpenProcessToken(
                    hProcess,
                    TokenAccessFlags.TOKEN_QUERY | TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES,
                    out IntPtr hToken);
                NativeMethods.CloseHandle(hProcess);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to get a token from the target process (PID = {0}).", pid);
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }

                Helpers.GetTokenPrivileges(hToken, out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                foreach (var priv in availablePrivs)
                {
                    if (Helpers.CompareIgnoreCase(priv.Key, privilegeName))
                    {
                        isAvailable = true;
                        privilegeName = priv.Key;
                        break;
                    }
                }

                if (!isAvailable)
                {
                    Console.WriteLine("[-] {0} is not available.", privilegeName);
                    break;
                }
                else
                {
                    if ((availablePrivs[privilegeName] & SE_PRIVILEGE_ATTRIBUTES.ENABLED) != 0)
                    {
                        Console.WriteLine("[*] {0} is already enabled.", privilegeName);
                        break;
                    }
                }

                status = Utilities.EnableTokenPrivileges(
                    hToken,
                    new List<string> { privilegeName },
                    out Dictionary<string, bool> adjustedPrivs);
                NativeMethods.CloseHandle(hToken);

                foreach (var priv in adjustedPrivs)
                {
                    if (priv.Value)
                        Console.WriteLine("[+] {0} is enabled successfully.", priv.Key);
                    else
                        Console.WriteLine("[-] Failed to enable {0}.", priv.Key);
                }
            } while (false);

            if (asSystem)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool FindPrivilegedProcess(string targetPrivilege, bool asSystem)
        {
            IntPtr hProcess;
            var processList = Process.GetProcesses();
            var privilegedProcesses = new Dictionary<int, string>();
            var deniedProcesses = new Dictionary<int, string>();

            Console.WriteLine();
            Console.WriteLine("[>] Searching process have {0}.", targetPrivilege);

            if (asSystem)
                if (!GetSystem())
                    return false;

            foreach (var proc in processList)
            {
                hProcess = NativeMethods.OpenProcess(
                    ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                    false,
                    proc.Id);

                if (hProcess == IntPtr.Zero)
                {
                    deniedProcesses.Add(proc.Id, proc.ProcessName);
                    continue;
                }

                if (!NativeMethods.OpenProcessToken(
                    hProcess,
                    TokenAccessFlags.TOKEN_QUERY,
                    out IntPtr hToken))
                {
                    deniedProcesses.Add(proc.Id, proc.ProcessName);
                    NativeMethods.CloseHandle(hProcess);
                    continue;
                }

                Helpers.GetTokenPrivileges(hToken, out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> privs);
                NativeMethods.CloseHandle(hToken);
                NativeMethods.CloseHandle(hProcess);

                foreach (var priv in privs.Keys)
                {
                    if (Helpers.CompareIgnoreCase(priv, targetPrivilege))
                    {
                        privilegedProcesses.Add(proc.Id, proc.ProcessName);
                        break;
                    }
                }
            }

            if (asSystem)
                NativeMethods.RevertToSelf();

            if (privilegedProcesses.Count == 0)
            {
                Console.WriteLine("[-] No process has {0}.", targetPrivilege);
            }
            else
            {
                if (privilegedProcesses.Count == 1)
                    Console.WriteLine("[+] Following process has {0}.", targetPrivilege);
                else
                    Console.WriteLine("[+] Following processes have {0}.", targetPrivilege);

                foreach (var proc in privilegedProcesses)
                    Console.WriteLine("    [*] {0} (PID : {1})", proc.Value, proc.Key);

                if (privilegedProcesses.Count == 1)
                    Console.WriteLine("[+] 1 process has {0}.", targetPrivilege);
                else
                    Console.WriteLine("[+] {0} processes have {1}.", privilegedProcesses.Count, targetPrivilege);
            }

            if (deniedProcesses.Count > 0)
            {
                if (deniedProcesses.Count == 1)
                    Console.WriteLine("[*] Access is denied by following 1 process.");
                else
                    Console.WriteLine("[*] Access is denied by following {0} processes.", deniedProcesses.Count);

                foreach (var denied in deniedProcesses)
                {
                    Console.WriteLine("    [*] {0} (PID : {1})", denied.Value, denied.Key);
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
                pid = Helpers.GetParentProcessId();

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

            hProcess = NativeMethods.OpenProcess(
                ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                if (asSystem)
                    NativeMethods.RevertToSelf();

                return false;
            }

            if (!NativeMethods.OpenProcessToken(
                hProcess,
                TokenAccessFlags.TOKEN_QUERY,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                NativeMethods.CloseHandle(hProcess);

                if (asSystem)
                    NativeMethods.RevertToSelf();

                return false;
            }

            bool isEnabled;
            Helpers.GetTokenPrivileges(hToken, out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> privs);

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
                isEnabled = ((priv.Value & SE_PRIVILEGE_ATTRIBUTES.ENABLED) != 0);
                Console.WriteLine("{0,-42} {1}", priv.Key, isEnabled ? "Enabled" : "Disabled");
            }

            Console.WriteLine("\n[*] Integrity Level : {0}\n", Helpers.GetTokenIntegrityLevelString(hToken));

            NativeMethods.CloseHandle(hToken);
            NativeMethods.CloseHandle(hProcess);

            if (asSystem)
                NativeMethods.RevertToSelf();

            return true;
        }


        private static bool GetSystem()
        {
            var status = false;
            var requiredPrivs = new List<string> {
                Win32Consts.SE_DEBUG_NAME,
                Win32Consts.SE_IMPERSONATE_NAME
            };

            Console.WriteLine("[>] Trying to get SYSTEM.");

            if (!Utilities.EnableTokenPrivileges(requiredPrivs, out Dictionary<string, bool> adjustedPrivs))
            {
                foreach (var priv in adjustedPrivs)
                {
                    if (!priv.Value)
                        Console.WriteLine("[-] Failed to enable {0}.", priv.Key);
                }

                Console.WriteLine("[!] Should be run with administrative privilege.");
            }
            else
            {
                status = Utilities.ImpersonateAsSmss();

                if (!status)
                    Console.WriteLine("[-] Failed to impersonate as smss.exe.");
            }

            return status;
        }


        public static bool RemoveAllPrivileges(int pid, bool asSystem)
        {
            int error;
            IntPtr hProcess;

            if (pid == 0)
                pid = Helpers.GetParentProcessId();

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


            hProcess = NativeMethods.OpenProcess(
                    ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                    false,
                    pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                if (asSystem)
                    NativeMethods.RevertToSelf();

                return false;
            }

            if (!NativeMethods.OpenProcessToken(
                hProcess,
                TokenAccessFlags.TOKEN_QUERY | TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                NativeMethods.CloseHandle(hProcess);

                if (asSystem)
                    NativeMethods.RevertToSelf();

                return false;
            }

            Helpers.GetTokenPrivileges(hToken, out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> privs);

            foreach (var priv in privs)
            {
                if (Utilities.RemoveSinglePrivilege(hToken, priv.Key))
                    Console.WriteLine("[+] {0} is removed successfully.", priv.Key);
            }

            Console.WriteLine("[*] Done.\n");

            NativeMethods.CloseHandle(hToken);
            NativeMethods.CloseHandle(hProcess);

            if (asSystem)
                NativeMethods.RevertToSelf();

            return true;
        }


        public static bool RemoveTokenPrivilege(int pid, string privilegeName, bool asSystem)
        {
            int error;
            IntPtr hProcess;

            if (pid == 0)
                pid = Helpers.GetParentProcessId();

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

            hProcess = NativeMethods.OpenProcess(
                ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                if (asSystem)
                    NativeMethods.RevertToSelf();

                return false;
            }

            if (!NativeMethods.OpenProcessToken(
                hProcess,
                TokenAccessFlags.TOKEN_QUERY | TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                NativeMethods.CloseHandle(hProcess);

                if (asSystem)
                    NativeMethods.RevertToSelf();

                return false;
            }

            bool isAvailable = false;
            Helpers.GetTokenPrivileges(hToken, out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> privs);

            foreach (var priv in privs.Keys)
            {
                if (Helpers.CompareIgnoreCase(priv, privilegeName))
                {
                    isAvailable = true;
                    break;
                }
            }

            if (!isAvailable)
            {
                Console.WriteLine("[-] {0} is already removed.\n", privilegeName);
                NativeMethods.CloseHandle(hToken);
                NativeMethods.CloseHandle(hProcess);

                if (asSystem)
                    NativeMethods.RevertToSelf();

                return false;
            }

            if (Utilities.RemoveSinglePrivilege(hToken, privilegeName))
                Console.WriteLine("[+] {0} is removed successfully.\n", privilegeName);

            NativeMethods.CloseHandle(hToken);
            NativeMethods.CloseHandle(hProcess);

            if (asSystem)
                NativeMethods.RevertToSelf();

            return true;
        }


        public static bool SetIntegrityLevel(int pid, int integrityLevelIndex, bool asSystem)
        {
            int error;
            IntPtr hProcess;
            string mandatoryLevelSid = Helpers.ConvertIndexToMandatoryLevelSid(integrityLevelIndex);

            if (pid == 0)
                pid = Helpers.GetParentProcessId();

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

            hProcess = NativeMethods.OpenProcess(
                ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open target process (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                if (asSystem)
                    NativeMethods.RevertToSelf();

                return false;
            }

            if (!NativeMethods.OpenProcessToken(
                hProcess,
                TokenAccessFlags.MAXIMUM_ALLOWED,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get target process token (PID = {0}).", pid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                NativeMethods.CloseHandle(hProcess);

                if (asSystem)
                    NativeMethods.RevertToSelf();

                return false;
            }

            Utilities.SetMandatoryLevel(hToken, mandatoryLevelSid);

            NativeMethods.CloseHandle(hToken);
            NativeMethods.CloseHandle(hProcess);

            if (asSystem)
                NativeMethods.RevertToSelf();

            return true;
        }
    }
}