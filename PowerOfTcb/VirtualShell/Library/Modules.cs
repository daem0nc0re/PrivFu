using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using VirtualShell.Interop;

namespace VirtualShell.Library
{
    internal class Modules
    {
        public static bool CreateVirtualAccountProcess(string command, bool bNewConsole)
        {
            int nDosErrorCode;
            bool bReverted = false;
            bool bDomainExists = false;
            var virtualDomainName = "VirtualDomain";
            var requiredPrivs = new List<SE_PRIVILEGE_ID>
            {
                SE_PRIVILEGE_ID.SeDebugPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege
            };
            bool bSuccess = Helpers.EnableTokenPrivileges(
                in requiredPrivs,
                out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs);
            nDosErrorCode = Marshal.GetLastWin32Error();

            foreach (var priv in adjustedPrivs)
            {
                if (priv.Value)
                    Console.WriteLine("[+] {0} is enabled successfully.", priv.Key);
                else
                    Console.WriteLine("[-] Failed to enable {0}.", priv.Key);
            }

            if (!bSuccess)
            {
                Console.WriteLine("[-] Insufficient privileges (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                return false;
            }

            requiredPrivs = new List<SE_PRIVILEGE_ID> {
                SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege,
                SE_PRIVILEGE_ID.SeTcbPrivilege
            };
            bSuccess = Utilities.ImpersonateAsWinlogon(
                in requiredPrivs,
                out adjustedPrivs);

            if (!bSuccess)
            {
                nDosErrorCode = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to impersonate as winlogon.exe (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
            }
            else
            {
                Console.WriteLine("[+] Impersonation as winlogon.exe is successful.");
                bSuccess = adjustedPrivs[SE_PRIVILEGE_ID.SeTcbPrivilege];
                bSuccess &= (adjustedPrivs[SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege] ||
                    adjustedPrivs[SE_PRIVILEGE_ID.SeImpersonatePrivilege]);

                if (!bSuccess)
                {
                    foreach (var priv in adjustedPrivs)
                    {
                        if (!priv.Value)
                            Console.WriteLine("[-] Failed to enable {0} for current thread.", priv.Key);
                    }

                    Helpers.RevertThreadToken(new IntPtr(-2));
                }
                else
                {
                    foreach (var priv in adjustedPrivs)
                    {
                        if (priv.Value)
                            Console.WriteLine("[+] {0} is enabled successfully for current thread.", priv.Key);
                    }
                }
            }

            if (!bSuccess)
                return false;

            do
            {
                IntPtr hToken;
                var virtualAccountName = "VirtualAdmin";
                var domainSid = "S-1-5-110";
                var accountSid = string.Format("{0}-500", domainSid);
                var tokenGroups = new Dictionary<string, SE_GROUP_ATTRIBUTES>
                {
                    {
                        // BUILTIN\Administrators
                        "S-1-5-32-544",
                        SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault | SE_GROUP_ATTRIBUTES.Mandatory
                    },
                    {
                        // NT AUTHORITY\LOCAL SERVICE
                        "S-1-5-19",
                        SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault | SE_GROUP_ATTRIBUTES.Mandatory
                    },
                    {
                        // NT SERVICE\TrustedInstaller
                        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
                        SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault | SE_GROUP_ATTRIBUTES.Mandatory
                    }
                };
                bSuccess = Helpers.AddSidMapping(virtualDomainName, null, domainSid);

                if (!bSuccess)
                {
                    nDosErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create a LocalService token (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                }
                else
                {
                    Console.WriteLine(@"[+] A virtual domain {0} is created successfully (SID: {1}).", virtualDomainName, domainSid);
                    bDomainExists = true;
                    bSuccess = Helpers.AddSidMapping(virtualDomainName, virtualAccountName, accountSid);

                    if (!bSuccess)
                    {
                        nDosErrorCode = Marshal.GetLastWin32Error();
                        Console.WriteLine("[-] Failed to create a LocalService token (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                    }
                    else
                    {
                        Console.WriteLine(@"[+] A virtual account {0}\{1} is created successfully (SID: {2}).",
                            virtualDomainName,
                            virtualAccountName,
                            accountSid);
                    }
                }

                if (!bSuccess)
                    break;

                hToken = Utilities.GetVirtualLogonToken(virtualAccountName, virtualDomainName, in tokenGroups);

                if (hToken == IntPtr.Zero)
                {
                    nDosErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create a virtual logon token (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                    bSuccess = false;
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a virtual logon token (Handle = 0x{0}).", hToken.ToString("X"));
                    Helpers.EnableAllTokenPrivileges(hToken, out Dictionary<SE_PRIVILEGE_ID, bool> _);

                    if (bNewConsole)
                    {
                        var nSessionId = Helpers.GetGuiSessionId();
                        Helpers.SetTokenSessionId(hToken, nSessionId);
                    }
                }

                bSuccess = Utilities.CreateTokenAssignedSuspendedProcess(
                    hToken,
                    command,
                    ref bNewConsole,
                    out PROCESS_INFORMATION processInfo);
                NativeMethods.NtClose(hToken);

                if (!bSuccess)
                {
                    nDosErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create a token assined process (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                }
                else
                {
                    Console.WriteLine("[+] Got a token assigned process (PID: {0}).", processInfo.dwProcessId);

                    if (Helpers.RemoveSidMapping(virtualDomainName, null))
                    {
                        bDomainExists = false;
                        Console.WriteLine("[+] {0} domain is removed successfully.", virtualDomainName);
                    }
                    else
                    {
                        nDosErrorCode = Marshal.GetLastWin32Error();
                        Console.WriteLine("[-] Failed to remove {0} domain (Error = 0x{0}).", virtualDomainName, nDosErrorCode.ToString("X8"));
                    }

                    bReverted = Helpers.RevertThreadToken(new IntPtr(-2));
                    NativeMethods.NtResumeThread(processInfo.hThread, out uint _);

                    if (!bNewConsole)
                        NativeMethods.NtWaitForSingleObject(processInfo.hProcess, false, IntPtr.Zero);

                    NativeMethods.NtClose(processInfo.hThread);
                    NativeMethods.NtClose(processInfo.hProcess);
                }
            } while (false);

            if (!bSuccess && bDomainExists)
            {
                if (Helpers.RemoveSidMapping(virtualDomainName, null))
                {
                    Console.WriteLine("[+] {0} domain is removed successfully.", virtualDomainName);
                }
                else
                {
                    nDosErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to remove {0} domain (Error = 0x{0}).", virtualDomainName, nDosErrorCode.ToString("X8"));
                }
            }

            if (!bReverted)
                Helpers.RevertThreadToken(new IntPtr(-2));

            return bSuccess;
        }
    }
}
