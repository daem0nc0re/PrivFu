using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using SwitchPriv.Interop;

namespace SwitchPriv.Library
{
    internal class Modules
    {
        public static bool DisableAllPrivileges(int pid, bool asSystem)
        {
            var status = false;
            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return status;
            }

            do
            {
                int error;
                IntPtr hProcess;
                var privsToDisable = new List<string>();

                Console.WriteLine("[>] Trying to disable all token privileges.");
                Console.WriteLine("    [*] Target PID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

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
                    if ((priv.Value & SE_PRIVILEGE_ATTRIBUTES.ENABLED) != 0)
                        privsToDisable.Add(priv.Key);
                }

                if (privsToDisable.Count == 0)
                {
                    Console.WriteLine("[*] All token privileges are already disabled.");
                    break;
                }

                status = Utilities.DisableTokenPrivileges(
                    hToken,
                    privsToDisable,
                    out Dictionary<string, bool> adjustedPrivs);
                NativeMethods.CloseHandle(hToken);

                foreach (var priv in adjustedPrivs)
                {
                    if (!priv.Value)
                        Console.WriteLine("[+] {0} is disabled successfully.", priv.Key);
                    else
                        Console.WriteLine("[-] Failed to disable {0}.", priv.Key);
                }
            } while (false);

            if (asSystem)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool DisableTokenPrivilege(int pid, string privilegeName, bool asSystem)
        {
            var status = false;
            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return status;
            }

            do
            {
                int error;
                IntPtr hProcess;
                var isAvailable = false;

                Console.WriteLine("[>] Trying to disable {0}.", privilegeName);
                Console.WriteLine("    [*] Target PID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

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
                    if ((availablePrivs[privilegeName] & SE_PRIVILEGE_ATTRIBUTES.ENABLED) == 0)
                    {
                        Console.WriteLine("[*] {0} is already disabled.", privilegeName);
                        break;
                    }
                }

                status = Utilities.DisableTokenPrivileges(
                    hToken,
                    new List<string> { privilegeName },
                    out Dictionary<string, bool> adjustedPrivs);
                NativeMethods.CloseHandle(hToken);

                foreach (var priv in adjustedPrivs)
                {
                    if (!priv.Value)
                        Console.WriteLine("[+] {0} is disabled successfully.", priv.Key);
                    else
                        Console.WriteLine("[-] Failed to disable {0}.", priv.Key);
                }
            } while (false);

            if (asSystem)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool EnableAllPrivileges(int pid, bool asSystem)
        {
            var status = false;
            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return status;
            }

            do
            {
                int error;
                IntPtr hProcess;
                var privsToEnable = new List<string>();

                Console.WriteLine("[>] Trying to enable all token privileges.");
                Console.WriteLine("    [*] Target PID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

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
            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return status;
            }

            do
            {
                int error;
                IntPtr hProcess;
                var isAvailable = false;

                Console.WriteLine("[>] Trying to enable {0}.", privilegeName);
                Console.WriteLine("    [*] Target PID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

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
            var privilegedProcesses = new Dictionary<int, string>();
            var deniedProcesses = new Dictionary<int, string>();

            do
            {
                bool status;
                IntPtr hProcess;

                Console.WriteLine("[>] Searching processes have {0}.", targetPrivilege);

                if (asSystem)
                {
                    asSystem = GetSystem();

                    if (!asSystem)
                        break;
                }

                foreach (var proc in Process.GetProcesses())
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

                    status = NativeMethods.OpenProcessToken(hProcess, TokenAccessFlags.TOKEN_QUERY, out IntPtr hToken);
                    NativeMethods.CloseHandle(hProcess);

                    if (!status)
                    {
                        deniedProcesses.Add(proc.Id, proc.ProcessName);
                        continue;
                    }

                    Helpers.GetTokenPrivileges(hToken, out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> privs);
                    NativeMethods.CloseHandle(hToken);

                    foreach (var priv in privs.Keys)
                    {
                        if (Helpers.CompareIgnoreCase(priv, targetPrivilege))
                        {
                            privilegedProcesses.Add(proc.Id, proc.ProcessName);
                            break;
                        }
                    }
                }

                if (privilegedProcesses.Count == 0)
                {
                    Console.WriteLine("[-] No process has {0}.", targetPrivilege);
                }
                else
                {
                    Console.WriteLine("[+] Got {0} process(es).", privilegedProcesses.Count);

                    foreach (var proc in privilegedProcesses)
                        Console.WriteLine("    [*] {0} (PID : {1})", proc.Value, proc.Key);
                }

                if (deniedProcesses.Count > 0)
                {
                    Console.WriteLine("[*] Access is denied by following {0} process(es).", deniedProcesses.Count);

                    foreach (var denied in deniedProcesses)
                        Console.WriteLine("    [*] {0} (PID : {1})", denied.Value, denied.Key);
                }
            } while (false);

            if (asSystem)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return (privilegedProcesses.Count > 0);
        }


        public static bool GetPrivileges(int pid, bool asSystem)
        {
            var status = false;
            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return status;
            }

            do
            {
                int error;
                IntPtr hProcess;
                bool isEnabled;
                var resultsBuilder = new StringBuilder();

                Console.WriteLine("[>] Trying to get available token privilege(s) for the target process.");
                Console.WriteLine("    [*] Target PID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

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
                    TokenAccessFlags.TOKEN_QUERY,
                    out IntPtr hToken);
                NativeMethods.CloseHandle(hProcess);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to get a token from the target process (PID = {0}).", pid);
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }

                status = Helpers.GetTokenPrivileges(hToken, out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                if (availablePrivs.Count > 0)
                {
                    resultsBuilder.Append(string.Format("[+] Got {0} token privilege(s).\n\n", availablePrivs.Count));
                    resultsBuilder.Append("PRIVILEGES INFORMATION\n");
                    resultsBuilder.Append("----------------------\n");
                    resultsBuilder.Append("Privilege Name                             State\n");
                    resultsBuilder.Append("========================================== ========\n");

                    foreach (var priv in availablePrivs)
                    {
                        isEnabled = ((priv.Value & SE_PRIVILEGE_ATTRIBUTES.ENABLED) != 0);
                        resultsBuilder.Append(string.Format("{0,-42} {1}\n", priv.Key, isEnabled ? "Enabled" : "Disabled"));
                    }

                    resultsBuilder.Append("\n");
                }
                else
                {
                    resultsBuilder.Append("[*] No available token privileges.\n");
                }

                resultsBuilder.Append(string.Format("[*] Integrity Level : {0}", Helpers.GetTokenIntegrityLevelString(hToken)));
                NativeMethods.CloseHandle(hProcess);

                Console.WriteLine(resultsBuilder.ToString());
                resultsBuilder.Clear();
            } while (false);

            if (asSystem)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
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

                if (status)
                    Console.WriteLine("[+] Got SYSTEM privilege.");
                else
                    Console.WriteLine("[-] Failed to impersonate as smss.exe.");
            }

            return status;
        }


        public static bool RemoveAllPrivileges(int pid, bool asSystem)
        {
            var status = false;
            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return status;
            }

            do
            {
                int error;
                IntPtr hProcess;
                var privsToRemove = new List<string>();

                Console.WriteLine("[>] Trying to remove all token privileges.");
                Console.WriteLine("    [*] Target PID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

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

                if (availablePrivs.Count == 0)
                {
                    Console.WriteLine("[*] All token privileges are already removed.");
                    break;
                }
                else
                {
                    foreach (var priv in availablePrivs)
                        privsToRemove.Add(priv.Key);
                }

                status = Utilities.RemoveTokenPrivileges(
                    hToken,
                    privsToRemove,
                    out Dictionary<string, bool> operationStatus);
                NativeMethods.CloseHandle(hToken);

                foreach (var priv in operationStatus)
                {
                    if (priv.Value)
                        Console.WriteLine("[+] {0} is removed successfully.", priv.Key);
                    else
                        Console.WriteLine("[-] Failed to remove {0}.", priv.Key);
                }
            } while (false);

            if (asSystem)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool RemoveTokenPrivilege(int pid, string privilegeName, bool asSystem)
        {
            var status = false;
            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return status;
            }

            do
            {
                int error;
                IntPtr hProcess;
                var isAvailable = false;

                Console.WriteLine("[>] Trying to remove {0}.", privilegeName);
                Console.WriteLine("    [*] Target PID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

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
                    Console.WriteLine("[*] {0} is already removed.", privilegeName);
                    break;
                }

                status = Utilities.RemoveTokenPrivileges(
                    hToken,
                    new List<string> { privilegeName },
                    out Dictionary<string, bool> operationStatus);
                NativeMethods.CloseHandle(hToken);

                foreach (var priv in operationStatus)
                {
                    if (priv.Value)
                        Console.WriteLine("[+] {0} is removed successfully.", priv.Key);
                    else
                        Console.WriteLine("[-] Failed to remove {0}.", priv.Key);
                }
            } while (false);

            if (asSystem)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool SetIntegrityLevel(int pid, int integrityLevelIndex, bool asSystem)
        {
            string mandatoryLevelSid = Helpers.ConvertIndexToMandatoryLevelSid(integrityLevelIndex);
            var status = false;
            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return status;
            }

            do
            {
                int error;
                IntPtr hProcess;

                Console.WriteLine("[>] Trying to update Integrity Level.");
                Console.WriteLine("    [*] Target PID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

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
                    TokenAccessFlags.TOKEN_ADJUST_DEFAULT,
                    out IntPtr hToken);
                NativeMethods.CloseHandle(hProcess);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to get a token from the target process (PID = {0}).", pid);
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }

                Console.WriteLine("[>] Trying to update Integrity Level to {0}.", ((MANDATORY_LEVEL_INDEX)integrityLevelIndex).ToString());

                status = Utilities.SetMandatoryLevel(hToken, mandatoryLevelSid);
                NativeMethods.CloseHandle(hToken);

                if (status)
                    Console.WriteLine("[+] Integrity Level is updated successfully.");
                else
                    Console.WriteLine("[-] Failed to update Integrity Level.");
            } while (false);

            if (asSystem)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }
    }
}