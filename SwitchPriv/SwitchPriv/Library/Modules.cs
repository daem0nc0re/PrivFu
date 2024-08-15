using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using SwitchPriv.Interop;

namespace SwitchPriv.Library
{
    internal class Modules
    {
        public static bool DisableAllPrivileges(int pid, bool bAsSystem)
        {
            var bSuccess = false;
            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return false;
            }

            do
            {
                IntPtr hToken;
                var privsToDisable = new List<SE_PRIVILEGE_ID>();

                Console.WriteLine("[>] Trying to disable all token privileges.");
                Console.WriteLine("    [*] Target PID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

                if (bAsSystem)
                {
                    bAsSystem = GetSystem();

                    if (!bAsSystem)
                        break;
                }

                hToken = Utilities.OpenProcessToken(pid, ACCESS_MASK.TOKEN_ADJUST_PRIVILEGES | ACCESS_MASK.TOKEN_QUERY);

                if (hToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to open the target process token (PID = {0}).", pid);
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(Marshal.GetLastWin32Error()));
                    break;
                }

                Helpers.GetTokenPrivileges(hToken, out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                foreach (var priv in availablePrivs)
                {
                    if ((priv.Value & SE_PRIVILEGE_ATTRIBUTES.Enabled) != 0)
                        privsToDisable.Add(priv.Key);
                }

                if (privsToDisable.Count == 0)
                {
                    bSuccess = true;
                    Console.WriteLine("[*] All token privileges are already disabled.");
                }
                else
                {
                    bSuccess = Utilities.DisableTokenPrivileges(
                        hToken,
                        in privsToDisable,
                        out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs);

                    foreach (var priv in adjustedPrivs)
                    {
                        if (!priv.Value)
                            Console.WriteLine("[+] {0} is disabled successfully.", priv.Key.ToString());
                        else
                            Console.WriteLine("[-] Failed to disable {0}.", priv.Key.ToString());
                    }
                }

                NativeMethods.NtClose(hToken);
            } while (false);

            if (bAsSystem)
                Helpers.RevertThreadToken(new IntPtr(-2));

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        public static bool DisableTokenPrivilege(int pid, string privilegeName, bool bAsSystem)
        {
            var bSuccess = false;

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
                IntPtr hToken;
                var privsToDisable = new List<SE_PRIVILEGE_ID>();

                Console.WriteLine("[>] Trying to disable a token privilege.");
                Console.WriteLine("    [*] Target PID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

                if (bAsSystem)
                {
                    bAsSystem = GetSystem();

                    if (!bAsSystem)
                        break;
                }

                hToken = Utilities.OpenProcessToken(pid, ACCESS_MASK.TOKEN_ADJUST_PRIVILEGES | ACCESS_MASK.TOKEN_QUERY);

                if (hToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to open the target process token (PID = {0}).", pid);
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(Marshal.GetLastWin32Error()));
                    break;
                }

                Helpers.GetTokenPrivileges(hToken, out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                foreach (var priv in availablePrivs)
                {
                    if (priv.Key.ToString().IndexOf(privilegeName, StringComparison.OrdinalIgnoreCase) != -1)
                        privsToDisable.Add(priv.Key);
                }

                if (privsToDisable.Count == 0)
                {
                    Console.WriteLine("[-] No candidates to disable.");
                }
                else if (privsToDisable.Count > 1)
                {
                    Console.WriteLine("[-] Cannot specify a unique privilege to disable.");

                    foreach (var priv in privsToDisable)
                        Console.WriteLine("    [*] {0}", priv.ToString());
                }
                else
                {
                    if ((availablePrivs[privsToDisable.First()] & SE_PRIVILEGE_ATTRIBUTES.Enabled) == 0)
                    {
                        bSuccess = true;
                        Console.WriteLine("[*] {0} is already disabled.", privsToDisable.First().ToString());
                    }
                    else
                    {
                        var disablePrivs = new List<SE_PRIVILEGE_ID> { privsToDisable.First() };
                        bSuccess = Utilities.DisableTokenPrivileges(
                            hToken,
                            in disablePrivs,
                            out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs);

                        foreach (var priv in adjustedPrivs)
                        {
                            if (!priv.Value)
                                Console.WriteLine("[+] {0} is disabled successfully.", priv.Key.ToString());
                            else
                                Console.WriteLine("[-] Failed to disable {0}.", priv.Key.ToString());
                        }
                    }
                }

                NativeMethods.NtClose(hToken);
            } while (false);

            if (bAsSystem)
                Helpers.RevertThreadToken(new IntPtr(-2));

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        public static bool EnableAllPrivileges(int pid, bool bAsSystem)
        {
            var bSuccess = false;
            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return false;
            }

            do
            {
                IntPtr hToken;
                var privsToEnable = new List<SE_PRIVILEGE_ID>();

                Console.WriteLine("[>] Trying to enable all token privileges.");
                Console.WriteLine("    [*] Target PID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

                if (bAsSystem)
                {
                    bAsSystem = GetSystem();

                    if (!bAsSystem)
                        break;
                }

                hToken = Utilities.OpenProcessToken(pid, ACCESS_MASK.TOKEN_ADJUST_PRIVILEGES | ACCESS_MASK.TOKEN_QUERY);

                if (hToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to open the target process token (PID = {0}).", pid);
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(Marshal.GetLastWin32Error()));
                    break;
                }

                Helpers.GetTokenPrivileges(hToken, out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                foreach (var priv in availablePrivs)
                {
                    if ((priv.Value & SE_PRIVILEGE_ATTRIBUTES.Enabled) == 0)
                        privsToEnable.Add(priv.Key);
                }

                if (privsToEnable.Count == 0)
                {
                    bSuccess = true;
                    Console.WriteLine("[*] All token privileges are already enabled.");
                }
                else
                {
                    bSuccess = Utilities.EnableTokenPrivileges(
                        hToken,
                        in privsToEnable,
                        out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs);

                    foreach (var priv in adjustedPrivs)
                    {
                        if (priv.Value)
                            Console.WriteLine("[+] {0} is enabled successfully.", priv.Key);
                        else
                            Console.WriteLine("[-] Failed to enable {0}.", priv.Key);
                    }
                }

                NativeMethods.NtClose(hToken);
            } while (false);

            if (bAsSystem)
                Helpers.RevertThreadToken(new IntPtr(-2));

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        public static bool EnableTokenPrivilege(int pid, string privilegeName, bool bAsSystem)
        {
            var bSuccess = false;

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
                IntPtr hToken;
                var privsToEnable = new List<SE_PRIVILEGE_ID>();

                Console.WriteLine("[>] Trying to enable a token privilege.");
                Console.WriteLine("    [*] Target PID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

                if (bAsSystem)
                {
                    bAsSystem = GetSystem();

                    if (!bAsSystem)
                        break;
                }

                hToken = Utilities.OpenProcessToken(pid, ACCESS_MASK.TOKEN_ADJUST_PRIVILEGES | ACCESS_MASK.TOKEN_QUERY);

                if (hToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to open the target process token (PID = {0}).", pid);
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(Marshal.GetLastWin32Error()));
                    break;
                }

                Helpers.GetTokenPrivileges(hToken, out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                foreach (var priv in availablePrivs)
                {
                    if (priv.Key.ToString().IndexOf(privilegeName, StringComparison.OrdinalIgnoreCase) != -1)
                        privsToEnable.Add(priv.Key);
                }

                if (privsToEnable.Count == 0)
                {
                    Console.WriteLine("[-] No candidates to enable.");
                }
                else if (privsToEnable.Count > 1)
                {
                    Console.WriteLine("[-] Cannot specify a unique privilege to enable.");

                    foreach (var priv in privsToEnable)
                        Console.WriteLine("    [*] {0}", priv);
                }
                else
                {
                    if ((availablePrivs[privsToEnable.First()] & SE_PRIVILEGE_ATTRIBUTES.Enabled) != 0)
                    {
                        bSuccess = true;
                        Console.WriteLine("[*] {0} is already enabled.", privsToEnable.First().ToString());
                    }
                    else
                    {
                        var requiredPrivs = new List<SE_PRIVILEGE_ID> { privsToEnable.First() };
                        bSuccess = Utilities.EnableTokenPrivileges(
                            hToken,
                            in requiredPrivs,
                            out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs);

                        foreach (var priv in adjustedPrivs)
                        {
                            if (priv.Value)
                                Console.WriteLine("[+] {0} is enabled successfully.", priv.Key.ToString());
                            else
                                Console.WriteLine("[-] Failed to enable {0}.", priv.Key.ToString());
                        }
                    }
                }
                
                NativeMethods.NtClose(hToken);
            } while (false);

            if (bAsSystem)
                Helpers.RevertThreadToken(new IntPtr(-2));

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        public static bool FilterTokenPrivilege(int pid, string[] privileges, bool asSystem)
        {
            var bSuccess = false;

            if (privileges.Length == 0)
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
                IntPtr hToken;
                var privsToRemain = new List<SE_PRIVILEGE_ID>();
                var privsToRemove = new List<SE_PRIVILEGE_ID>();

                Console.WriteLine("[>] Trying to remove all token privileges except one.");
                Console.WriteLine("    [*] Target PID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

                if (asSystem)
                {
                    asSystem = GetSystem();

                    if (!asSystem)
                        break;
                }

                hToken = Utilities.OpenProcessToken(pid, ACCESS_MASK.TOKEN_ADJUST_PRIVILEGES | ACCESS_MASK.TOKEN_QUERY);

                if (hToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to open the target process token (PID = {0}).", pid);
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(Marshal.GetLastWin32Error()));
                    break;
                }

                Helpers.GetTokenPrivileges(hToken, out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                foreach (var priv in availablePrivs)
                {
                    var bRemain = false;

                    foreach (var privilegeName in privileges)
                    {
                        if (priv.Key.ToString().IndexOf(privilegeName, StringComparison.OrdinalIgnoreCase) != -1)
                        {
                            bRemain = true;
                            break;
                        }
                    }

                    if (bRemain)
                        privsToRemain.Add(priv.Key);
                    else
                        privsToRemove.Add(priv.Key);
                }

                if (privsToRemain.Count == 0)
                {
                    Console.WriteLine("[-] No candidates to remain.");
                }
                else if (privsToRemain.Count > 1)
                {
                    Console.WriteLine("[>] Trying to remove privileges other than follows.");

                    foreach (var priv in privsToRemain)
                        Console.WriteLine("    [*] {0}", priv);

                    bSuccess = Utilities.RemoveTokenPrivileges(
                        hToken,
                        in privsToRemove,
                        out Dictionary<SE_PRIVILEGE_ID, bool> removedStatus);

                    foreach (var priv in removedStatus)
                    {
                        if (priv.Value)
                            Console.WriteLine("[+] {0} is removed successfully.", priv.Key);
                        else
                            Console.WriteLine("[-] Failed to remove {0}.", priv.Key);
                    }
                }
                else
                {
                    Console.WriteLine("[>] Trying to remove all privileges except for {0}.", privsToRemain.First().ToString());
                    bSuccess = Utilities.RemoveTokenPrivileges(
                        hToken,
                        in privsToRemove,
                        out Dictionary<SE_PRIVILEGE_ID, bool> removedStatus);

                    foreach (var priv in removedStatus)
                    {
                        if (priv.Value)
                            Console.WriteLine("[+] {0} is removed successfully.", priv.Key);
                        else
                            Console.WriteLine("[-] Failed to remove {0}.", priv.Key);
                    }
                }

                NativeMethods.NtClose(hToken);
            } while (false);

            if (asSystem)
                Helpers.RevertThreadToken(new IntPtr(-2));

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        public static bool GetPrivileges(int pid, bool bAsSystem)
        {
            var bSuccess = false;
            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return false;
            }

            do
            {
                IntPtr hToken;
                var resultsBuilder = new StringBuilder();

                Console.WriteLine("[>] Trying to get available token privilege(s) for the target process.");
                Console.WriteLine("    [*] Target PID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

                if (bAsSystem)
                {
                    bAsSystem = GetSystem();

                    if (!bAsSystem)
                        break;
                }

                hToken = Utilities.OpenProcessToken(pid, ACCESS_MASK.TOKEN_QUERY);

                if (hToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to open the target process token (PID = {0}).", pid);
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(Marshal.GetLastWin32Error()));
                    break;
                }

                bSuccess = Helpers.GetTokenPrivileges(hToken, out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);
                Helpers.GetTokenIntegrityLevel(hToken, out string _, out string integrityLevel, out SID_NAME_USE _);
                NativeMethods.NtClose(hToken);

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

                        infoToPrint.Add(priv.Key.ToString(), infoState);

                        if (priv.Key.ToString().Length > widths[0])
                            widths[0] = priv.Key.ToString().Length;

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

                if (!string.IsNullOrEmpty(integrityLevel))
                    integrityLevel = integrityLevel.Split('\\')[1];

                resultsBuilder.AppendFormat("[*] Integrity Level : {0}", integrityLevel ?? "N/A");
                Console.WriteLine(resultsBuilder.ToString());
                resultsBuilder.Clear();
            } while (false);

            if (bAsSystem)
                Helpers.RevertThreadToken(new IntPtr(-2));

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        private static bool GetSystem()
        {
            var bSuccess = false;
            var requiredPrivs = new List<SE_PRIVILEGE_ID> {
                SE_PRIVILEGE_ID.SeDebugPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege
            };

            Console.WriteLine("[>] Trying to get SYSTEM.");

            if (!Utilities.EnableTokenPrivileges(in requiredPrivs, out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs))
            {
                foreach (var priv in adjustedPrivs)
                {
                    if (!priv.Value)
                        Console.WriteLine("[-] Failed to enable {0}.", priv.Key.ToString());
                }

                Console.WriteLine("[!] Should be run with administrative privilege.");
            }
            else
            {
                bSuccess = Utilities.ImpersonateAsSmss();

                if (bSuccess)
                    Console.WriteLine("[+] Got SYSTEM privilege.");
                else
                    Console.WriteLine("[-] Failed to impersonate as smss.exe.");
            }

            return bSuccess;
        }


        public static bool RemoveAllPrivileges(int pid, bool bAsSystem)
        {
            var bSuccess = false;
            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return false;
            }

            do
            {
                IntPtr hToken;
                var privsToRemove = new List<SE_PRIVILEGE_ID>();

                Console.WriteLine("[>] Trying to remove all token privileges.");
                Console.WriteLine("    [*] Target PID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

                if (bAsSystem)
                {
                    bAsSystem = GetSystem();

                    if (!bAsSystem)
                        break;
                }

                hToken = Utilities.OpenProcessToken(pid, ACCESS_MASK.TOKEN_ADJUST_PRIVILEGES | ACCESS_MASK.TOKEN_QUERY);

                if (hToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to open the target process token (PID = {0}).", pid);
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(Marshal.GetLastWin32Error()));
                    break;
                }

                Helpers.GetTokenPrivileges(hToken, out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                if (availablePrivs.Count == 0)
                {
                    bSuccess = true;
                    Console.WriteLine("[*] All token privileges are already removed.");
                }
                else
                {
                    foreach (var priv in availablePrivs)
                        privsToRemove.Add(priv.Key);

                    bSuccess = Utilities.RemoveTokenPrivileges(
                        hToken,
                        privsToRemove,
                        out Dictionary<SE_PRIVILEGE_ID, bool> removedStatus);

                    foreach (var priv in removedStatus)
                    {
                        if (priv.Value)
                            Console.WriteLine("[+] {0} is removed successfully.", priv.Key);
                        else
                            Console.WriteLine("[-] Failed to remove {0}.", priv.Key);
                    }
                }

                NativeMethods.NtClose(hToken);
            } while (false);

            if (bAsSystem)
                Helpers.RevertThreadToken(new IntPtr(-2));

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        public static bool RemoveTokenPrivilege(int pid, string privilegeName, bool bAsSystem)
        {
            var bSuccess = false;

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
                IntPtr hToken;
                var privsToRemove = new List<SE_PRIVILEGE_ID>();

                Console.WriteLine("[>] Trying to remove a token privilege.");
                Console.WriteLine("    [*] Target PID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

                if (bAsSystem)
                {
                    bAsSystem = GetSystem();

                    if (!bAsSystem)
                        break;
                }

                hToken = Utilities.OpenProcessToken(pid, ACCESS_MASK.TOKEN_ADJUST_PRIVILEGES | ACCESS_MASK.TOKEN_QUERY);

                if (hToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to open the target process token (PID = {0}).", pid);
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(Marshal.GetLastWin32Error()));
                    break;
                }

                Helpers.GetTokenPrivileges(hToken, out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                foreach (var priv in availablePrivs)
                {
                    if (priv.Key.ToString().IndexOf(privilegeName, StringComparison.OrdinalIgnoreCase) != -1)
                        privsToRemove.Add(priv.Key);
                }

                if (privsToRemove.Count == 0)
                {
                    Console.WriteLine("[-] No candidates to remove.");
                }
                else if (privsToRemove.Count > 1)
                {
                    Console.WriteLine("[-] Cannot specify a unique privilege to remove.");

                    foreach (var priv in privsToRemove)
                        Console.WriteLine("    [*] {0}", priv.ToString());
                }
                else
                {
                    bSuccess = Utilities.RemoveTokenPrivileges(
                        hToken,
                        new List<SE_PRIVILEGE_ID> { privsToRemove.First() },
                        out Dictionary<SE_PRIVILEGE_ID, bool> removedStatus);

                    foreach (var priv in removedStatus)
                    {
                        if (priv.Value)
                            Console.WriteLine("[+] {0} is removed successfully.", priv.Key.ToString());
                        else
                            Console.WriteLine("[-] Failed to remove {0}.", priv.Key.ToString());
                    }
                }
                
                NativeMethods.NtClose(hToken);
            } while (false);

            if (bAsSystem)
                Helpers.RevertThreadToken(new IntPtr(-2));

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        public static bool SearchPrivilegedProcess(string privilegeName, bool bAsSystem)
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
                if (Helpers.GetFullPrivilegeName(privilegeName, out List<SE_PRIVILEGE_ID> candidatePrivs))
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
                }
                else
                {
                    Console.WriteLine("[-] Failed to specify a unique privilege to search.");
                }

                Console.WriteLine("[>] Searching processes have {0}.", privilegeName);

                if (bAsSystem)
                {
                    bAsSystem = GetSystem();

                    if (!bAsSystem)
                        break;
                }

                foreach (var proc in Process.GetProcesses())
                {
                    IntPtr hToken = Utilities.OpenProcessToken(proc.Id, ACCESS_MASK.TOKEN_QUERY);

                    if (hToken == IntPtr.Zero)
                    {
                        deniedProcesses.Add(proc.Id, proc.ProcessName);
                        continue;
                    }

                    Helpers.GetTokenPrivileges(hToken, out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> privs);
                    NativeMethods.NtClose(hToken);

                    foreach (var priv in privs.Keys)
                    {
                        if (priv == candidatePrivs.First())
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

            if (bAsSystem)
                Helpers.RevertThreadToken(new IntPtr(-2));

            Console.WriteLine("[*] Done.");

            return (privilegedProcesses.Count > 0);
        }


        public static bool SetIntegrityLevel(int pid, int integrityLevelIndex, bool bAsSystem)
        {
            int rid = -1;
            var bSuccess = false;
            pid = Utilities.ResolveProcessId(pid, out string processName);

            if (pid == -1)
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.");
                return false;
            }

            if (integrityLevelIndex == 0) // Untrusted
                rid = 0;
            else if (integrityLevelIndex == 1) // Low
                rid = 0x1000;
            else if (integrityLevelIndex == 2) // Medium
                rid = 0x2000;
            else if (integrityLevelIndex == 3) // Medium Plus
                rid = 0x2100;
            else if (integrityLevelIndex == 4) // High
                rid = 0x3000;
            else if (integrityLevelIndex == 5) // System
                rid = 0x4000;
            else if (integrityLevelIndex == 6) // Protected (should be invalid)
                rid = 0x5000;

            if (rid == -1)
            {
                Console.WriteLine("[-] Invalid integrity level option.");
                return false;
            }

            do
            {
                IntPtr hToken;

                Console.WriteLine("[>] Trying to update Integrity Level.");
                Console.WriteLine("    [*] Target PID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

                if (bAsSystem)
                {
                    bAsSystem = GetSystem();

                    if (!bAsSystem)
                        break;
                }

                hToken = Utilities.OpenProcessToken(pid, ACCESS_MASK.TOKEN_ADJUST_DEFAULT);

                if (hToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to open the target process token (PID = {0}).", pid);
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(Marshal.GetLastWin32Error()));
                    break;
                }

                Console.WriteLine("[>] Trying to update Integrity Level to {0}.", ((MANDATORY_LABEL_RID)rid).ToString());

                bSuccess = Utilities.SetMandatoryLevel(hToken, rid);
                NativeMethods.NtClose(hToken);

                if (bSuccess)
                {
                    Console.WriteLine("[+] Integrity Level is updated successfully.");
                }
                else
                {
                    Console.WriteLine("[-] Failed to update Integrity Level.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(Marshal.GetLastWin32Error()));
                }
            } while (false);

            if (bAsSystem)
                Helpers.RevertThreadToken(new IntPtr(-2));

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }
    }
}