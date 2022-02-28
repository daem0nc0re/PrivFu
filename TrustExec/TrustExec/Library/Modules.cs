using System;
using System.Security.Principal;
using TrustExec.Interop;

namespace TrustExec.Library
{
    class Modules
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
            var privs = new string[] {
                Win32Const.SE_DEBUG_NAME,
                Win32Const.SE_IMPERSONATE_NAME
            };

            if (!Utilities.EnableMultiplePrivileges(hCurrentToken, privs))
                return false;

            privs = new string[] {
                Win32Const.SE_ASSIGNPRIMARYTOKEN_NAME,
                Win32Const.SE_INCREASE_QUOTA_NAME
            };

            if (!Utilities.ImpersonateAsSmss(privs))
                return false;

            bool status = Utilities.AddVirtualAccount(domain, username, domainRid);
            Win32Api.RevertToSelf();

            return status;
        }


        public static bool LookupSid(string domain, string username, string sid)
        {
            string result;
            string accountName;

            if (!string.IsNullOrEmpty(sid))
            {
                result = Helpers.ConvertSidStringToAccountName(
                    sid,
                    out Win32Const.SID_NAME_USE peUse);

                if (!string.IsNullOrEmpty(result))
                {
                    Console.WriteLine(
                        "\n[*] Result : {0} (SID : {1})\n",
                        result.ToLower(),
                        sid.ToUpper());

                    return true;
                }
                else
                {
                    Console.WriteLine("\n[*] No result.\n");

                    return false;
                }
            }
            else if (!string.IsNullOrEmpty(domain) || !string.IsNullOrEmpty(username))
            {
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
                    Console.WriteLine(
                        "\n[*] Result : {0} (SID : {1})\n",
                        accountName.ToLower(),
                        result);

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
            var privs = new string[] {
                Win32Const.SE_DEBUG_NAME,
                Win32Const.SE_IMPERSONATE_NAME
            };

            if (!Utilities.EnableMultiplePrivileges(hCurrentToken, privs))
                return false;

            privs = new string[] {
                Win32Const.SE_ASSIGNPRIMARYTOKEN_NAME,
                Win32Const.SE_INCREASE_QUOTA_NAME
            };

            if (!Utilities.ImpersonateAsSmss(privs))
                return false;

            bool status = Utilities.RemoveVirtualAccount(domain, username);
            Win32Api.RevertToSelf();

            return status;
        }


        public static bool RunTrustedInstallerProcess(string command, bool full)
        {
            string execute;

            if (string.IsNullOrEmpty(command))
            {
                execute = "C:\\Windows\\System32\\cmd.exe";
            }
            else
            {
                execute = string.Format(
                    "C:\\Windows\\System32\\cmd.exe /c \"{0}\"",
                    command);
            }

            Console.WriteLine();
            Console.WriteLine("[>] Trying to get SYSTEM.");

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            var privs = new string[] {
                Win32Const.SE_DEBUG_NAME,
                Win32Const.SE_IMPERSONATE_NAME
            };

            if (!Utilities.EnableMultiplePrivileges(hCurrentToken, privs))
                return false;

            privs = new string[] {
                Win32Const.SE_CREATE_TOKEN_NAME,
                Win32Const.SE_ASSIGNPRIMARYTOKEN_NAME
            };

            if (!Utilities.ImpersonateAsSmss(privs))
                return false;

            IntPtr hToken = Utilities.CreateTrustedInstallerToken(
                Win32Const.TOKEN_TYPE.TokenPrimary,
                Win32Const.SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous,
                full);

            if (hToken == IntPtr.Zero)
                return false;

            bool status = Utilities.CreateTokenAssignedProcess(hToken, execute);
            Win32Api.CloseHandle(hToken);
            Win32Api.RevertToSelf();

            return status;
        }


        public static bool RunTrustedInstallerProcessWithVirtualLogon(
            string domain,
            string username,
            int domainRid,
            string command,
            bool fullPrivilege)
        {
            string execute;

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
            {
                execute = "C:\\Windows\\System32\\cmd.exe";
            }
            else
            {
                execute = string.Format(
                    "C:\\Windows\\System32\\cmd.exe /c \"{0}\"",
                    command);
            }

            Console.WriteLine();
            Console.WriteLine("[>] Trying to get SYSTEM.");

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            var privs = new string[] {
                Win32Const.SE_DEBUG_NAME,
                Win32Const.SE_IMPERSONATE_NAME
            };

            if (!Utilities.EnableMultiplePrivileges(hCurrentToken, privs))
                return false;

            privs = new string[] {
                Win32Const.SE_ASSIGNPRIMARYTOKEN_NAME,
                Win32Const.SE_INCREASE_QUOTA_NAME
            };

            if (!Utilities.ImpersonateAsSmss(privs))
                return false;

            IntPtr hToken = Utilities.CreateTrustedInstallerTokenWithVirtualLogon(
                domain,
                username,
                domainRid);

            if (hToken == IntPtr.Zero)
                return false;

            if (fullPrivilege)
                Utilities.EnableAllPrivileges(hToken);

            bool status = Utilities.CreateTokenAssignedProcess(hToken, execute);
            Win32Api.CloseHandle(hToken);
            Win32Api.RevertToSelf();

            return status;
        }
    }
}
