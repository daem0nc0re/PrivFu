using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using TrustExec.Interop;

namespace TrustExec.Library
{
    internal class Modules
    {
        public static bool AddVirtualAccount(string domain, string username, int domainRid)
        {
            if (string.IsNullOrEmpty(domain))
            {
                Console.WriteLine("[!] Domain name is not specified.");

                return false;
            }

            Console.WriteLine("[>] Trying to get SYSTEM.");

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            var privs = new List<string> {
                Win32Consts.SE_DEBUG_NAME,
                Win32Consts.SE_IMPERSONATE_NAME
            };

            if (!Utilities.EnableTokenPrivileges(hCurrentToken, privs, out Dictionary<string, bool> _))
                return false;

            privs = new List<string> {
                Win32Consts.SE_ASSIGNPRIMARYTOKEN_NAME,
                Win32Consts.SE_INCREASE_QUOTA_NAME
            };

            Console.WriteLine("[>] Trying to impersonate as smss.exe.");

            if (!Utilities.ImpersonateAsSmss(privs))
            {
                Console.WriteLine("[-] Failed to impersonation.");
                return false;
            }
            else
            {
                Console.WriteLine("[+] Impersonation is successful.");
            }

            bool status = Utilities.AddVirtualAccount(domain, username, domainRid);
            NativeMethods.RevertToSelf();

            return status;
        }


        public static bool LookupSid(string domain, string username, string sid)
        {
            var status = false;
            var peUse = SID_NAME_USE.Unknown;

            if ((!string.IsNullOrEmpty(domain) || !string.IsNullOrEmpty(username)) && !string.IsNullOrEmpty(sid))
                Console.WriteLine("[!] Username or domain name should not be specified with SID at a time.");
            else if (!string.IsNullOrEmpty(domain) || !string.IsNullOrEmpty(username))
                status = Helpers.ConvertAccountNameToSidString(ref username, ref domain, out sid, out peUse);
            else if (!string.IsNullOrEmpty(sid))
                status = Helpers.ConvertSidStringToAccountName(ref sid, out username, out domain, out peUse);
            else
                Console.WriteLine("[!] SID, domain name or username to lookup is required.");

            if (status)
            {
                string accountName;

                if (!string.IsNullOrEmpty(domain) && !string.IsNullOrEmpty(username))
                    accountName = string.Format(@"{0}\{1}", domain, username);
                else if (!string.IsNullOrEmpty(username))
                    accountName = username;
                else if (!string.IsNullOrEmpty(domain))
                    accountName = domain;
                else
                    accountName = "N/A";

                Console.WriteLine("[*] Result:");
                Console.WriteLine("    [*] Account Name : {0}", accountName);
                Console.WriteLine("    [*] SID          : {0}", sid  ?? "N/A");
                Console.WriteLine("    [*] Account Type : {0}", peUse.ToString());
            }
            else
            {
                Console.WriteLine("[*] No result.");
            }

            return status;
        }


        public static bool RemoveVirtualAccount(string domain, string username)
        {
            if (string.IsNullOrEmpty(domain))
            {
                Console.WriteLine("[!] Domain name is not specified.");
                return false;
            }

            Console.WriteLine("[>] Trying to get SYSTEM.");

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            var privs = new List<string> {
                Win32Consts.SE_DEBUG_NAME,
                Win32Consts.SE_IMPERSONATE_NAME
            };

            if (!Utilities.EnableTokenPrivileges(hCurrentToken, privs, out Dictionary<string, bool> _))
                return false;

            privs = new List<string> {
                Win32Consts.SE_ASSIGNPRIMARYTOKEN_NAME,
                Win32Consts.SE_INCREASE_QUOTA_NAME
            };

            Console.WriteLine("[>] Trying to impersonate as smss.exe.");

            if (!Utilities.ImpersonateAsSmss(privs))
            {
                Console.WriteLine("[-] Failed to impersonation.");
                return false;
            }
            else
            {
                Console.WriteLine("[+] Impersonation is successful.");
            }

            bool status = Utilities.RemoveVirtualAccount(domain, username);
            NativeMethods.RevertToSelf();

            return status;
        }


        public static bool RunTrustedInstallerProcess(string command, string extraSidsString, bool full)
        {
            bool status;
            string execute;
            string[] extraSidsArray;
            var isImpersonated = false;

            if (string.IsNullOrEmpty(command))
                execute = @"C:\Windows\System32\cmd.exe";
            else
                execute = command;

            if (string.IsNullOrEmpty(extraSidsString))
                extraSidsArray = new string[] { };
            else
                extraSidsArray = Helpers.ParseGroupSids(extraSidsString);

            Console.WriteLine();

            do
            {
                IntPtr hToken;
                var privs = new List<string> {
                    Win32Consts.SE_ASSIGNPRIMARYTOKEN_NAME,
                    Win32Consts.SE_CREATE_TOKEN_NAME,
                    Win32Consts.SE_INCREASE_QUOTA_NAME
                };

                Console.WriteLine("[>] Trying to get SYSTEM.");

                status = Utilities.EnableTokenPrivileges(
                    WindowsIdentity.GetCurrent().Token,
                    new List<string> { Win32Consts.SE_DEBUG_NAME, Win32Consts.SE_IMPERSONATE_NAME },
                    out Dictionary<string, bool> adjustedPrivs);

                if (!status)
                {
                    foreach (var priv in adjustedPrivs)
                    {
                        if (!priv.Value)
                            Console.WriteLine("[-] {0} is not available.", priv.Key);
                    }

                    break;
                }

                isImpersonated = Utilities.ImpersonateAsSmss(privs);

                if (!isImpersonated)
                {
                    Console.WriteLine("[-] Failed to impersonation.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Impersonation is successful.");
                }

                hToken = Utilities.CreateTrustedInstallerToken(
                    TOKEN_TYPE.TokenPrimary,
                    SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous,
                    extraSidsArray,
                    full);

                if (hToken == IntPtr.Zero)
                    break;

                Console.WriteLine("[>] Trying to create token assigned process.");

                status = Utilities.CreateTokenAssignedProcess(hToken, execute);
                NativeMethods.CloseHandle(hToken);

                if (!status)
                {
                    var error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create token assigned process.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                }
            } while (false);

            if (isImpersonated)
                NativeMethods.RevertToSelf();

            return status;
        }


        public static bool RunTrustedInstallerProcessWithVirtualLogon(
            string domain,
            string username,
            int domainRid,
            string command,
            string extraSidsString,
            bool fullPrivilege)
        {
            bool status;
            string execute;
            string[] extraSidsArray;

            if (string.IsNullOrEmpty(domain))
            {
                Console.WriteLine("[!] Domain name is not specified.");

                return false;
            }

            if (string.IsNullOrEmpty(username))
            {
                Console.WriteLine("[!] Username is not specified.");
                return false;
            }

            if (string.IsNullOrEmpty(command))
                execute = @"C:\Windows\System32\cmd.exe";
            else
                execute = command;

            Console.WriteLine();

            if (string.IsNullOrEmpty(extraSidsString))
                extraSidsArray = new string[] { };
            else
                extraSidsArray = Helpers.ParseGroupSids(extraSidsString);

            Console.WriteLine("[>] Trying to get SYSTEM.");

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            var privs = new List<string> {
                Win32Consts.SE_DEBUG_NAME,
                Win32Consts.SE_IMPERSONATE_NAME
            };

            if (!Utilities.EnableTokenPrivileges(hCurrentToken, privs, out Dictionary<string, bool> _))
                return false;

            privs = new List<string> {
                Win32Consts.SE_ASSIGNPRIMARYTOKEN_NAME,
                Win32Consts.SE_INCREASE_QUOTA_NAME
            };

            Console.WriteLine("[>] Trying to impersonate as smss.exe.");

            if (!Utilities.ImpersonateAsSmss(privs))
            {
                Console.WriteLine("[-] Failed to impersonation.");
                return false;
            }
            else
            {
                Console.WriteLine("[+] Impersonation is successful.");
            }

            IntPtr hToken = Utilities.CreateTrustedInstallerTokenWithVirtualLogon(
                domain,
                username,
                domainRid,
                extraSidsArray);

            if (hToken == IntPtr.Zero)
                return false;

            if (fullPrivilege)
                Utilities.EnableAllTokenPrivileges(hToken, out Dictionary<string, bool> _);

            Console.WriteLine("[>] Trying to create token assigned process.");

            status = Utilities.CreateTokenAssignedProcess(hToken, execute);
            NativeMethods.CloseHandle(hToken);

            if (!status)
            {
                var error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to create token assigned process.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
            }

            NativeMethods.RevertToSelf();

            return status;
        }
    }
}
