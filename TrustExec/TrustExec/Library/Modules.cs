using System;
using System.Collections.Generic;
using System.Security.Principal;
using TrustExec.Interop;

namespace TrustExec.Library
{
    internal class Modules
    {
        public static bool AddVirtualAccount(
            string domain,
            string username,
            int domainRid)
        {
            if (string.IsNullOrEmpty(domain))
            {
                Console.WriteLine("[!] Domain name is not specified.\n");

                return false;
            }

            Console.WriteLine();
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


        public static bool LookupSid(
            string domain,
            string username,
            string sid)
        {
            string result;
            string accountName;

            if ((!string.IsNullOrEmpty(domain) || !string.IsNullOrEmpty(username)) &&
                !string.IsNullOrEmpty(sid))
            {
                Console.WriteLine("\n[!] Username or domain name should not be specified with SID at a time.\n");

                return false;
            }
            else if (!string.IsNullOrEmpty(domain) || !string.IsNullOrEmpty(username))
            {
                if (!string.IsNullOrEmpty(domain) && domain.Trim() == ".")
                    domain = Environment.MachineName;

                if (!string.IsNullOrEmpty(domain) && !string.IsNullOrEmpty(username))
                    accountName = string.Format(@"{0}\{1}", domain, username);
                else if (!string.IsNullOrEmpty(domain))
                    accountName = domain;
                else if (!string.IsNullOrEmpty(username))
                    accountName = username;
                else
                    return false;

                result = Helpers.ConvertAccountNameToSidString(
                    ref accountName,
                    out SID_NAME_USE peUse);

                if (!string.IsNullOrEmpty(result))
                {
                    Console.WriteLine();
                    Console.WriteLine("[*] Result:");
                    Console.WriteLine("    |-> Account Name : {0}", accountName);
                    Console.WriteLine("    |-> SID          : {0}", result);
                    Console.WriteLine("    |-> Account Type : {0}", peUse.ToString());
                    Console.WriteLine();

                    return true;
                }
                else
                {
                    Console.WriteLine("\n[*] No result.\n");

                    return false;
                }
            }
            else if (!string.IsNullOrEmpty(sid))
            {
                sid = sid.ToUpper();
                result = Helpers.ConvertSidStringToAccountName(
                    ref sid,
                    out SID_NAME_USE peUse);

                if (!string.IsNullOrEmpty(result))
                {
                    Console.WriteLine();
                    Console.WriteLine("[*] Result:");
                    Console.WriteLine("    |-> Account Name : {0}", result);
                    Console.WriteLine("    |-> SID          : {0}", sid);
                    Console.WriteLine("    |-> Account Type : {0}", peUse.ToString());
                    Console.WriteLine();

                    return true;
                }
                else
                {
                    Console.WriteLine("\n[*] No result.\n");

                    return false;
                }
            }
            else
            {
                Console.WriteLine("\n[!] SID, domain name or username to lookup is required.\n");

                return false;
            }
        }


        public static bool RemoveVirtualAccount(string domain, string username)
        {
            if (string.IsNullOrEmpty(domain))
            {
                Console.WriteLine("[!] Domain name is not specified.\n");

                return false;
            }

            Console.WriteLine();
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

                status = Utilities.CreateTokenAssignedProcess(hToken, execute);
                NativeMethods.CloseHandle(hToken);
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
            string execute;
            string[] extraSidsArray;

            if (string.IsNullOrEmpty(domain))
            {
                Console.WriteLine("[!] Domain name is not specified.\n");

                return false;
            }

            if (string.IsNullOrEmpty(username))
            {
                Console.WriteLine("[!] Username is not specified.\n");

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

            bool status = Utilities.CreateTokenAssignedProcess(hToken, execute);
            NativeMethods.CloseHandle(hToken);
            NativeMethods.RevertToSelf();

            return status;
        }
    }
}
