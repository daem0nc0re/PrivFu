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
                return false;
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
                    if ((priv.Value & SE_PRIVILEGE_ATTRIBUTES.Enabled) != 0)
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

            if (string.IsNullOrEmpty(privilegeName))
            {
                Console.WriteLine("[-] Privilege name is required.");
                return false;
            }

            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return false;
            }

            do
            {
                int error;
                IntPtr hProcess;
                var candidatePrivs = new List<string>();

                Console.WriteLine("[>] Trying to disable a token privilege.");
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
                    if (priv.Key.IndexOf(privilegeName, StringComparison.OrdinalIgnoreCase) != -1)
                        candidatePrivs.Add(priv.Key);
                }

                if (candidatePrivs.Count == 0)
                {
                    Console.WriteLine("[-] No candidates to disable.");
                    break;
                }
                else if (candidatePrivs.Count > 1)
                {
                    Console.WriteLine("[-] Cannot specify a unique privilege to disable.");

                    foreach (var priv in candidatePrivs)
                        Console.WriteLine("    [*] {0}", priv);

                    break;
                }
                else
                {
                    privilegeName = candidatePrivs[0];

                    if ((availablePrivs[privilegeName] & SE_PRIVILEGE_ATTRIBUTES.Enabled) == 0)
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
                return false;
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
                    if ((priv.Value & SE_PRIVILEGE_ATTRIBUTES.Enabled) == 0)
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

            if (string.IsNullOrEmpty(privilegeName))
            {
                Console.WriteLine("[-] Privilege name is required.");
                return false;
            }

            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return false;
            }

            do
            {
                int error;
                IntPtr hProcess;
                var candidatePrivs = new List<string>();

                Console.WriteLine("[>] Trying to enable a token privilege.");
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
                    if (priv.Key.IndexOf(privilegeName, StringComparison.OrdinalIgnoreCase) != -1)
                        candidatePrivs.Add(priv.Key);
                }

                if (candidatePrivs.Count == 0)
                {
                    Console.WriteLine("[-] No candidates to enable.");
                    break;
                }
                else if (candidatePrivs.Count > 1)
                {
                    Console.WriteLine("[-] Cannot specify a unique privilege to enable.");

                    foreach (var priv in candidatePrivs)
                        Console.WriteLine("    [*] {0}", priv);

                    break;
                }
                else
                {
                    privilegeName = candidatePrivs[0];

                    if ((availablePrivs[privilegeName] & SE_PRIVILEGE_ATTRIBUTES.Enabled) != 0)
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


        public static bool FilterTokenPrivilege(int pid, string privilegeName, bool asSystem)
        {
            var status = false;

            if (string.IsNullOrEmpty(privilegeName))
            {
                Console.WriteLine("[-] Privilege name is required.");
                return false;
            }

            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return false;
            }

            do
            {
                int error;
                IntPtr hProcess;
                var candidatePrivs = new List<string>();
                var privsToRemove = new List<string>();

                Console.WriteLine("[>] Trying to remove all token privileges except one.");
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
                    if (priv.Key.IndexOf(privilegeName, StringComparison.OrdinalIgnoreCase) != -1)
                        candidatePrivs.Add(priv.Key);
                    else
                        privsToRemove.Add(priv.Key);
                }

                if (candidatePrivs.Count == 0)
                {
                    Console.WriteLine("[-] No candidates to remove.");
                    break;
                }
                else if (candidatePrivs.Count > 1)
                {
                    Console.WriteLine("[-] Cannot specify a unique privilege to remove.");

                    foreach (var priv in candidatePrivs)
                        Console.WriteLine("    [*] {0}", priv);

                    break;
                }
                else
                {
                    Console.WriteLine("[>] Trying to remove all privileges except for {0}.", candidatePrivs[0]);
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


        public static bool GetPrivileges(int pid, bool asSystem)
        {
            var status = false;
            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return false;
            }

            do
            {
                int error;
                IntPtr hProcess;
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
                    var titles = new string[] { "Privilege Name", "State" };
                    var widths = new int[titles.Length];
                    var infoToPrint = new Dictionary<string, string>();

                    for (var idx = 0; idx < titles.Length; idx++)
                        widths[idx] = titles[idx].Length;

                    foreach (var priv in availablePrivs)
                    {
                        var infoState = priv.Value.ToString();

                        if (priv.Value == SE_PRIVILEGE_ATTRIBUTES.EnabledByDefault)
                            infoState = "EnabledByDefault, Disabled";

                        infoToPrint.Add(priv.Key, infoState);

                        if (priv.Key.Length > widths[0])
                            widths[0] = priv.Key.Length;

                        if (infoState.Length > widths[1])
                            widths[1] = infoState.Length;
                    }

                    var lineFormat = string.Format("{{0,-{0}}} {{1,-{1}}}\n", widths[0], widths[1]);

                    resultsBuilder.AppendFormat("[+] Got {0} token privilege(s).\n\n", infoToPrint.Count);
                    resultsBuilder.Append("PRIVILEGES INFORMATION\n");
                    resultsBuilder.Append("----------------------\n\n");
                    resultsBuilder.AppendFormat(lineFormat, titles[0], titles[1]);
                    resultsBuilder.AppendFormat(lineFormat, new string('=', widths[0]), new string('=', widths[1]));

                    foreach (var priv in infoToPrint)
                        resultsBuilder.AppendFormat(lineFormat, priv.Key, priv.Value.ToString());

                    resultsBuilder.Append("\n");
                }
                else
                {
                    resultsBuilder.Append("[*] No available token privileges.\n");
                }

                resultsBuilder.AppendFormat("[*] Integrity Level : {0}", Helpers.GetTokenIntegrityLevelString(hToken));
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
                return false;
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

            if (string.IsNullOrEmpty(privilegeName))
            {
                Console.WriteLine("[-] Privilege name is required.");
                return false;
            }

            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return false;
            }

            do
            {
                int error;
                IntPtr hProcess;
                var candidatePrivs = new List<string>();

                Console.WriteLine("[>] Trying to remove a token privilege.");
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
                    if (priv.Key.IndexOf(privilegeName, StringComparison.OrdinalIgnoreCase) != -1)
                        candidatePrivs.Add(priv.Key);
                }

                if (candidatePrivs.Count == 0)
                {
                    Console.WriteLine("[-] No candidates to remove.");
                    break;
                }
                else if (candidatePrivs.Count > 1)
                {
                    Console.WriteLine("[-] Cannot specify a unique privilege to remove.");

                    foreach (var priv in candidatePrivs)
                        Console.WriteLine("    [*] {0}", priv);

                    break;
                }
                else
                {
                    privilegeName = candidatePrivs[0];
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


        public static bool SearchPrivilegedProcess(string privilegeName, bool asSystem)
        {
            var privilegedProcesses = new Dictionary<int, string>();
            var deniedProcesses = new Dictionary<int, string>();

            if (string.IsNullOrEmpty(privilegeName))
            {
                Console.WriteLine("[-] Privilege name is required.");
                return false;
            }

            do
            {
                bool status;
                IntPtr hProcess;

                if (Helpers.GetFullPrivilegeName(privilegeName, out List<string> candidatePrivs))
                {
                    if (candidatePrivs.Count > 1)
                    {
                        Console.WriteLine("[-] Cannot specify a unique privilege to search.");

                        foreach (var priv in candidatePrivs)
                            Console.WriteLine("    [*] {0}", priv);

                        break;
                    }
                    else if (candidatePrivs.Count == 0)
                    {
                        Console.WriteLine("[-] No candidates to search.");
                    }
                    else
                    {
                        privilegeName = candidatePrivs[0];
                    }
                }
                else
                {
                    Console.WriteLine("[-] Failed to specify a unique privilege to search.");
                }

                Console.WriteLine("[>] Searching processes have {0}.", privilegeName);

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
                        if (Helpers.CompareIgnoreCase(priv, privilegeName))
                        {
                            privilegedProcesses.Add(proc.Id, proc.ProcessName);
                            break;
                        }
                    }
                }

                if (privilegedProcesses.Count == 0)
                {
                    Console.WriteLine("[-] No process has {0}.", privilegeName);
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


        public static bool SetIntegrityLevel(int pid, int integrityLevelIndex, bool asSystem)
        {
            string mandatoryLevelSid;
            var status = false;
            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return false;
            }

            switch (integrityLevelIndex)
            {
                case 0:
                    mandatoryLevelSid = "S-1-16-0"; // Untrusted
                    break;
                case 1:
                    mandatoryLevelSid = "S-1-16-4096"; // Low
                    break;
                case 2:
                    mandatoryLevelSid = "S-1-16-8192"; // Medium
                    break;
                case 3:
                    mandatoryLevelSid = "S-1-16-8448"; // Medium Plus
                    break;
                case 4:
                    mandatoryLevelSid = "S-1-16-12288"; // High
                    break;
                case 5:
                    mandatoryLevelSid = "S-1-16-16384"; // System
                    break;
                case 6:
                    mandatoryLevelSid = "S-1-16-20480"; // Protected (should be invalid)
                    break;
                case 7:
                    mandatoryLevelSid = "S-1-16-28672"; // Secure (should be invalid)
                    break;
                default:
                    return false;
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