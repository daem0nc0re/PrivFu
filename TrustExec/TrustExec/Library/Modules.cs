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

            var requiredPrivs = new List<SE_PRIVILEGE_ID> {
                SE_PRIVILEGE_ID.SeDebugPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege
            };
            bool bSuccess = Helpers.EnableTokenPrivileges(
                WindowsIdentity.GetCurrent().Token,
                in requiredPrivs,
                out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs);

            foreach (var priv in adjustedPrivs)
            {
                if (priv.Value)
                    Console.WriteLine("[+] {0} is enabled successfully.", priv.Key.ToString());
                else
                    Console.WriteLine("[-] Failed to enabled {0}.", priv.Key.ToString());
            }

            if (!bSuccess)
            {
                Console.WriteLine("[-] Insufficient privileges.");
                return false;
            }

            requiredPrivs = new List<SE_PRIVILEGE_ID> {
                SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege,
                SE_PRIVILEGE_ID.SeIncreaseQuotaPrivilege
            };

            Console.WriteLine("[>] Trying to impersonate as smss.exe.");

            if (!Utilities.ImpersonateAsSmss(in requiredPrivs))
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

            var requiredPrivs = new List<SE_PRIVILEGE_ID> {
                SE_PRIVILEGE_ID.SeDebugPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege
            };
            bool bSuccess = Helpers.EnableTokenPrivileges(
                WindowsIdentity.GetCurrent().Token,
                in requiredPrivs,
                out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs);

            foreach (var priv in adjustedPrivs)
            {
                if (priv.Value)
                    Console.WriteLine("[+] {0} is enabled successfully.", priv.Key.ToString());
                else
                    Console.WriteLine("[-] Failed to enabled {0}.", priv.Key.ToString());
            }

            if (!bSuccess)
            {
                Console.WriteLine("[-] Insufficient privileges.");
                return false;
            }

            requiredPrivs = new List<SE_PRIVILEGE_ID> {
                SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege,
                SE_PRIVILEGE_ID.SeIncreaseQuotaPrivilege
            };

            Console.WriteLine("[>] Trying to impersonate as smss.exe.");

            if (!Utilities.ImpersonateAsSmss(in requiredPrivs))
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
            bool bSuccess;
            bool bIsImpersonated;
            string execute;
            string[] extraSidsArray;

            if (string.IsNullOrEmpty(command))
                execute = Environment.GetEnvironmentVariable("COMSPEC");
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
                var requiredPrivs = new List<SE_PRIVILEGE_ID> {
                    SE_PRIVILEGE_ID.SeDebugPrivilege,
                    SE_PRIVILEGE_ID.SeImpersonatePrivilege
                };

                Console.WriteLine("[>] Trying to get SYSTEM.");

                bSuccess = Helpers.EnableTokenPrivileges(
                WindowsIdentity.GetCurrent().Token,
                in requiredPrivs,
                out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs);

                foreach (var priv in adjustedPrivs)
                {
                    if (priv.Value)
                        Console.WriteLine("[+] {0} is enabled successfully.", priv.Key.ToString());
                    else
                        Console.WriteLine("[-] Failed to enabled {0}.", priv.Key.ToString());
                }

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Insufficient privileges.");
                    return false;
                }

                requiredPrivs = new List<SE_PRIVILEGE_ID>
                {
                    SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege,
                    SE_PRIVILEGE_ID.SeCreateTokenPrivilege,
                    SE_PRIVILEGE_ID.SeIncreaseQuotaPrivilege
                };
                bIsImpersonated = Utilities.ImpersonateAsSmss(in requiredPrivs);

                if (!bIsImpersonated)
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

                bSuccess = Utilities.CreateTokenAssignedProcess(hToken, execute);
                NativeMethods.CloseHandle(hToken);

                if (!bSuccess)
                {
                    var error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create token assigned process.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                }
            } while (false);

            if (bIsImpersonated)
                NativeMethods.RevertToSelf();

            return bSuccess;
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
                execute = Environment.GetEnvironmentVariable("COMSPEC");
            else
                execute = command;

            Console.WriteLine();

            if (string.IsNullOrEmpty(extraSidsString))
                extraSidsArray = new string[] { };
            else
                extraSidsArray = Helpers.ParseGroupSids(extraSidsString);

            Console.WriteLine("[>] Trying to get SYSTEM.");

            var requiredPrivs = new List<SE_PRIVILEGE_ID> {
                SE_PRIVILEGE_ID.SeDebugPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege
            };
            bool bSuccess = Helpers.EnableTokenPrivileges(
                WindowsIdentity.GetCurrent().Token,
                in requiredPrivs,
                out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs);

            foreach (var priv in adjustedPrivs)
            {
                if (priv.Value)
                    Console.WriteLine("[+] {0} is enabled successfully.", priv.Key.ToString());
                else
                    Console.WriteLine("[-] Failed to enabled {0}.", priv.Key.ToString());
            }

            if (!bSuccess)
            {
                Console.WriteLine("[-] Insufficient privileges.");
                return false;
            }

            requiredPrivs = new List<SE_PRIVILEGE_ID> {
                SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege,
                SE_PRIVILEGE_ID.SeIncreaseQuotaPrivilege
            };

            Console.WriteLine("[>] Trying to impersonate as smss.exe.");

            if (!Utilities.ImpersonateAsSmss(in requiredPrivs))
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
                Helpers.EnableAllTokenPrivileges(hToken, out Dictionary<SE_PRIVILEGE_ID, bool> _);

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
