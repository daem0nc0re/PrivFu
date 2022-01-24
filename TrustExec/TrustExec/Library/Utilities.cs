using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using TrustExec.Interop;

namespace TrustExec.Library
{
    class Utilities
    {
        public static bool AddVirtualAccount(string domain, string username, int groupId)
        {
            int error;
            int ntstatus;
            int expectedNtStatus = Convert.ToInt32("0xC000000D", 16);
            string groupSid = string.Format("S-1-5-{0}", groupId);
            string userSid = string.Format("S-1-5-{0}-110", groupId);

            if ((groupId >= 0 && groupId < 21) || groupId == 32 ||
                groupId == 64 || groupId == 80 || groupId == 83 ||
                groupId == 113 || groupId == 114)
            {
                Console.WriteLine("[!] {0} is reserved.", groupSid);
                return false;
            }

            Console.WriteLine("[>] Trying to add virtual domain and user.");
            Console.WriteLine("    |-> Domain   : {0} ({1})", domain, groupSid);
            Console.WriteLine("    |-> Username : {0} ({1})", username, userSid);

            if (!Win32Api.ConvertStringSidToSid(
                groupSid,
                out IntPtr pSidDomain))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to initialize virtual domain SID.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                return false;
            }

            if (!Win32Api.ConvertStringSidToSid(
                userSid,
                out IntPtr pSidUser))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to initialize virtual domain SID.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                return false;
            }

            ntstatus = Helpers.AddSidMapping(domain, null, pSidDomain);
            if (ntstatus == Win32Const.STATUS_SUCCESS)
            {
                Helpers.AddSidMapping(domain, username, pSidUser);
                Console.WriteLine("[+] Added virtual domain and user.");
            }
            else if (ntstatus == expectedNtStatus)
            {
                Console.WriteLine("[*] {0} or {1} maybe already exists or invalid.", groupSid, domain);
            }
            else
            {
                Console.WriteLine("[-] Unexpected error.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(ntstatus, true));
                return false;
            }

            return true;
        }


        public static bool CreateTokenAssignedProcess(
            IntPtr hToken,
            string command)
        {
            int error;
            var startupInfo = new Win32Struct.STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(startupInfo);
            startupInfo.lpDesktop = "Winsta0\\Default";

            Console.WriteLine("[>] Trying to create process.\n");

            bool status = Win32Api.CreateProcessAsUser(
                hToken,
                null,
                command,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                0,
                IntPtr.Zero,
                Environment.CurrentDirectory,
                ref startupInfo,
                out Win32Struct.PROCESS_INFORMATION processInformation);

            if (!status)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to create new process.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                return false;
            }

            Win32Api.WaitForSingleObject(processInformation.hProcess, uint.MaxValue);
            Win32Api.CloseHandle(processInformation.hThread);
            Win32Api.CloseHandle(processInformation.hProcess);

            return true;
        }


        public static IntPtr CreateTrustedInstallerTokenWithVirtualLogon(
            string domain,
            string username,
            int groupId)
        {
            int error;

            Console.WriteLine("[>] Trying to generate token group information.");

            if (!Win32Api.ConvertStringSidToSid(
                Win32Const.DOMAIN_ALIAS_RID_ADMINS,
                out IntPtr pAdminGroup))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get Administrator group SID.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                return IntPtr.Zero;
            }

            if (!Win32Api.ConvertStringSidToSid(
                Win32Const.TRUSTED_INSTALLER_RID,
                out IntPtr pTrustedInstaller))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get Trusted Installer SID.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                return IntPtr.Zero;
            }

            if (!Win32Api.ConvertStringSidToSid(
                Win32Const.SYSTEM_MANDATORY_LEVEL,
                out IntPtr pSystemIntegrity))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get System Integrity Level SID.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                return IntPtr.Zero;
            }

            var tokenGroups = new Win32Struct.TOKEN_GROUPS
            {
                GroupCount = 2,
                Groups = new Win32Struct.SID_AND_ATTRIBUTES[16]
            };

            tokenGroups.Groups[0].Sid = pAdminGroup;
            tokenGroups.Groups[0].Attributes = (uint)(
                Win32Const.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                Win32Const.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT |
                Win32Const.SE_GROUP_ATTRIBUTES.SE_GROUP_MANDATORY);
            tokenGroups.Groups[1].Sid = pTrustedInstaller;
            tokenGroups.Groups[1].Attributes = (uint)(
                Win32Const.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                Win32Const.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT |
                Win32Const.SE_GROUP_ATTRIBUTES.SE_GROUP_OWNER);

            var pTokenGroups = Marshal.AllocHGlobal(Marshal.SizeOf(tokenGroups));
            Marshal.StructureToPtr(tokenGroups, pTokenGroups, true);

            if (!AddVirtualAccount(domain, username, groupId))
                return IntPtr.Zero;

            Console.WriteLine("[>] Trying to logon as {0}\\{1}.", domain, username);

            if (!Win32Api.LogonUserExExW(
                username,
                domain,
                string.Empty,
                Win32Const.LOGON32_LOGON_INTERACTIVE,
                Win32Const.LOGON32_PROVIDER_VIRTUAL,
                pTokenGroups,
                out IntPtr hToken,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to logon as virtual account.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                return IntPtr.Zero;
            }

            IntPtr pLinkedToken = Helpers.GetInformationFromToken(hToken,
                Win32Const.TOKEN_INFORMATION_CLASS.TokenLinkedToken);

            if (pLinkedToken == IntPtr.Zero)
                return IntPtr.Zero;

            var linkedToken = (Win32Struct.TOKEN_LINKED_TOKEN)Marshal.PtrToStructure(
                pLinkedToken,
                typeof(Win32Struct.TOKEN_LINKED_TOKEN));

            hToken = linkedToken.LinkedToken;

            var mandatoryLabel = new Win32Struct.TOKEN_MANDATORY_LABEL();
            mandatoryLabel.Label.Sid = pSystemIntegrity;
            mandatoryLabel.Label.Attributes = (uint)(
                Win32Const.SE_GROUP_ATTRIBUTES.SE_GROUP_INTEGRITY |
                Win32Const.SE_GROUP_ATTRIBUTES.SE_GROUP_INTEGRITY_ENABLED);

            IntPtr pMandatoryLabel = Marshal.AllocHGlobal(Marshal.SizeOf(mandatoryLabel));
            Marshal.StructureToPtr(mandatoryLabel, pMandatoryLabel, true);

            if (!Win32Api.SetTokenInformation(
                hToken,
                Win32Const.TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                pMandatoryLabel,
                Marshal.SizeOf(mandatoryLabel)))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get System Integrity Level SID.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Marshal.FreeHGlobal(pMandatoryLabel);
                return IntPtr.Zero;
            }

            Marshal.FreeHGlobal(pMandatoryLabel);

            return hToken;
        }


        public static void EnableAllPrivileges(IntPtr hToken)
        {
            Dictionary<Win32Struct.LUID, uint> privs = GetAvailablePrivileges(hToken);
            bool isEnabled;

            foreach (var priv in privs)
            {
                isEnabled = ((priv.Value & (uint)Win32Const.SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED) != 0);

                if (!isEnabled)
                {
                    EnableSinglePrivilege(hToken, priv.Key);
                }
            }
        }


        public static bool EnableSinglePrivilege(IntPtr hToken, Win32Struct.LUID priv)
        {
            int error;

            var tp = new Win32Struct.TOKEN_PRIVILEGES(1);
            tp.Privileges[0].Luid = priv;
            tp.Privileges[0].Attributes = (uint)Win32Const.SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED;

            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(tp));
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            Console.WriteLine("[>] Trying to enable {0}.", Helpers.GetPrivilegeName(priv));

            if (!Win32Api.AdjustTokenPrivileges(
                hToken,
                false,
                pTokenPrivilege,
                0,
                IntPtr.Zero,
                IntPtr.Zero))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to enable {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            error = Marshal.GetLastWin32Error();

            if (error != 0)
            {
                Console.WriteLine("[-] Failed to enable {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                return false;
            }

            Console.WriteLine("[+] {0} is enabled successfully.", Helpers.GetPrivilegeName(priv));

            return true;
        }


        public static Dictionary<string, bool> EnableMultiplePrivileges(
            IntPtr hToken,
            List<string> privilegeNames)
        {
            Dictionary<string, bool> results = new Dictionary<string, bool>();
            var availablePrivs = GetAvailablePrivileges(hToken);
            bool isEnabled;

            foreach (var name in privilegeNames)
            {
                results.Add(name, false);
            }

            foreach (var priv in availablePrivs)
            {
                foreach (var name in privilegeNames)
                {
                    if (Helpers.GetPrivilegeName(priv.Key) == name)
                    {
                        isEnabled = ((priv.Value & (uint)Win32Const.SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED) != 0);

                        if (isEnabled)
                        {
                            results[name] = true;
                        }
                        else
                        {
                            results[name] = EnableSinglePrivilege(hToken, priv.Key);
                        }
                    }
                }
            }

            return results;
        }


        public static Dictionary<Win32Struct.LUID, uint> GetAvailablePrivileges(
            IntPtr hToken)
        {
            int ERROR_INSUFFICIENT_BUFFER = 122;
            int error;
            bool status;
            int bufferLength = Marshal.SizeOf(typeof(Win32Struct.TOKEN_PRIVILEGES));
            var availablePrivs = new Dictionary<Win32Struct.LUID, uint>();
            IntPtr pTokenPrivileges;

            do
            {
                pTokenPrivileges = Marshal.AllocHGlobal(bufferLength);
                Helpers.ZeroMemory(pTokenPrivileges, bufferLength);

                status = Win32Api.GetTokenInformation(
                    hToken,
                    Win32Const.TOKEN_INFORMATION_CLASS.TokenPrivileges,
                    pTokenPrivileges,
                    bufferLength,
                    out bufferLength);
                error = Marshal.GetLastWin32Error();

                if (!status)
                    Marshal.FreeHGlobal(pTokenPrivileges);
            } while (!status && (error == ERROR_INSUFFICIENT_BUFFER));

            if (!status)
                return availablePrivs;

            int privCount = Marshal.ReadInt32(pTokenPrivileges);
            IntPtr buffer = new IntPtr(pTokenPrivileges.ToInt64() + Marshal.SizeOf(privCount));

            for (var count = 0; count < privCount; count++)
            {
                var luidAndAttr = (Win32Struct.LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                    buffer,
                    typeof(Win32Struct.LUID_AND_ATTRIBUTES));

                availablePrivs.Add(luidAndAttr.Luid, luidAndAttr.Attributes);
                buffer = new IntPtr(buffer.ToInt64() + Marshal.SizeOf(luidAndAttr));
            }

            Marshal.FreeHGlobal(pTokenPrivileges);

            return availablePrivs;
        }


        public static bool ImpersonateAsSmss()
        {
            int error;
            int smss;

            Console.WriteLine("[>] Trying to impersonate as smss.exe.");

            try
            {
                smss = (Process.GetProcessesByName("smss")[0]).Id;
            }
            catch
            {
                Console.WriteLine("[-] Failed to get process id of smss.exe.\n");
                return false;
            }

            IntPtr hProcess = Win32Api.OpenProcess(
                Win32Const.ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                true,
                smss);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get handle to smss.exe process.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                Win32Const.TokenAccessFlags.TOKEN_DUPLICATE,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get handle to smss.exe process token.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hProcess);
                return false;
            }

            Win32Api.CloseHandle(hProcess);

            if (!Win32Api.DuplicateTokenEx(
                hToken,
                Win32Const.TokenAccessFlags.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                Win32Const.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                Win32Const.TOKEN_TYPE.TokenPrimary,
                out IntPtr hDupToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to duplicate smss.exe process token.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hToken);
                return false;
            }

            List<string> privilegeNames = new List<string> {
                Win32Const.SE_ASSIGNPRIMARYTOKEN_NAME,
                Win32Const.SE_INCREASE_QUOTA_NAME
            };

            var privilegeStatus = EnableMultiplePrivileges(
                hDupToken,
                privilegeNames);

            foreach (var status in privilegeStatus.Values)
            {
                if (!status)
                {
                    Win32Api.CloseHandle(hDupToken);
                    Win32Api.CloseHandle(hToken);
                    return false;
                }
            }

            if (!Win32Api.ImpersonateLoggedOnUser(hDupToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to impersonate logon user.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hDupToken);
                Win32Api.CloseHandle(hToken);
                return false;
            }

            Console.WriteLine("[+] Impersonation is successful.");

            Win32Api.CloseHandle(hDupToken);
            Win32Api.CloseHandle(hToken);

            return true;
        }


        public static bool RemoveVirtualAccount(string domain, string username)
        {
            int expectedNtStatus = Convert.ToInt32("0xC0000225", 16);

            Console.WriteLine("[>] Trying to remove SID.");
            Console.WriteLine("    |-> Domain   : {0}", domain);

            if (username == string.Empty)
                username = null;

            if (username != null)
                Console.WriteLine("    |-> Username : {0}", username);

            int ntstatus = Helpers.RemoveSidMapping(domain, username);

            if (ntstatus == expectedNtStatus)
            {
                Console.WriteLine("[-] Requested SID is not exist.\n");
                return false;
            }

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                Console.WriteLine("[!] Unexpected error.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(ntstatus, true));
                return false;
            }

            Console.WriteLine("[+] Requested SID is removed successfully.\n");

            return true;
        }
    }
}
