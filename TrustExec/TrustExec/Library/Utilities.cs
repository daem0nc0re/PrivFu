using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using TrustExec.Interop;

namespace TrustExec.Library
{
    class Utilities
    {
        public static bool AddVirtualAccount(
            string domain,
            string username,
            int domainRid)
        {
            int error;
            uint ntstatus;
            string domainSid = string.Format("S-1-5-{0}", domainRid);
            string userSid = string.Format("S-1-5-{0}-110", domainRid);

            if (string.IsNullOrEmpty(domain) || string.IsNullOrEmpty(username))
            {
                Console.WriteLine("[!] Domain name and username are required.");
                return false;
            }

            if ((domainRid >= 0 && domainRid < 21) || domainRid == 32 ||
                domainRid == 64 || domainRid == 80 || domainRid == 83 ||
                domainRid == 113 || domainRid == 114)
            {
                Console.WriteLine("[!] {0} is reserved.", domainSid);

                return false;
            }

            Console.WriteLine("[>] Trying to add virtual domain and user.");
            Console.WriteLine("    |-> Domain   : {0} (SID : {1})", domain, domainSid);
            Console.WriteLine("    |-> Username : {0} (SID : {1})", username, userSid);

            if (!Win32Api.ConvertStringSidToSid(
                domainSid,
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
            else if (ntstatus == Win32Const.STATUS_INVALID_PARAMETER)
            {
                Console.WriteLine("[*] {0} or {1} maybe already exists or invalid.", domainSid, domain);
            }
            else
            {
                Console.WriteLine("[-] Unexpected error.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage((int)ntstatus, true));
                
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

            Console.WriteLine("[>] Trying to create a token assigned process.\n");

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


        public static bool CreateTokenPrivileges(
            string[] privs,
            out Win32Struct.TOKEN_PRIVILEGES tokenPrivileges)
        {
            int error;
            int sizeOfStruct = Marshal.SizeOf(typeof(Win32Struct.TOKEN_PRIVILEGES));
            IntPtr pPrivileges = Marshal.AllocHGlobal(sizeOfStruct);

            tokenPrivileges = (Win32Struct.TOKEN_PRIVILEGES)Marshal.PtrToStructure(
                pPrivileges,
                typeof(Win32Struct.TOKEN_PRIVILEGES));
            tokenPrivileges.PrivilegeCount = privs.Length;

            for (var idx = 0; idx < tokenPrivileges.PrivilegeCount; idx++)
            {
                if (!Win32Api.LookupPrivilegeValue(
                    null,
                    privs[idx],
                    out Win32Struct.LUID luid))
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to lookup LUID for {0}.", privs[idx]);
                    Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                    return false;
                }

                tokenPrivileges.Privileges[idx].Attributes = (uint)(
                    Win32Const.SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED |
                    Win32Const.SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED_BY_DEFAULT);
                tokenPrivileges.Privileges[idx].Luid = luid;
            }

            return true;
        }


        public static IntPtr CreateTrustedInstallerToken(
            Win32Const.TOKEN_TYPE tokenType,
            Win32Const.SECURITY_IMPERSONATION_LEVEL impersonationLevel,
            bool full)
        {
            int error;
            uint ntstatus;
            Win32Struct.LUID authId = Win32Const.SYSTEM_LUID;
            var tokenSource = new Win32Struct.TOKEN_SOURCE("*SYSTEM*");
            tokenSource.SourceIdentifier.HighPart = 0;
            tokenSource.SourceIdentifier.LowPart = 0;
            string[] privs;

            if (full)
            {
                privs = new string[] {
                    Win32Const.SE_CREATE_TOKEN_NAME,
                    Win32Const.SE_ASSIGNPRIMARYTOKEN_NAME,
                    Win32Const.SE_LOCK_MEMORY_NAME,
                    Win32Const.SE_INCREASE_QUOTA_NAME,
                    Win32Const.SE_MACHINE_ACCOUNT_NAME,
                    Win32Const.SE_TCB_NAME,
                    Win32Const.SE_SECURITY_NAME,
                    Win32Const.SE_TAKE_OWNERSHIP_NAME,
                    Win32Const.SE_LOAD_DRIVER_NAME,
                    Win32Const.SE_SYSTEM_PROFILE_NAME,
                    Win32Const.SE_SYSTEMTIME_NAME,
                    Win32Const.SE_PROFILE_SINGLE_PROCESS_NAME,
                    Win32Const.SE_INCREASE_BASE_PRIORITY_NAME,
                    Win32Const.SE_CREATE_PAGEFILE_NAME,
                    Win32Const.SE_CREATE_PERMANENT_NAME,
                    Win32Const.SE_BACKUP_NAME,
                    Win32Const.SE_RESTORE_NAME,
                    Win32Const.SE_SHUTDOWN_NAME,
                    Win32Const.SE_DEBUG_NAME,
                    Win32Const.SE_AUDIT_NAME,
                    Win32Const.SE_SYSTEM_ENVIRONMENT_NAME,
                    Win32Const.SE_CHANGE_NOTIFY_NAME,
                    Win32Const.SE_REMOTE_SHUTDOWN_NAME,
                    Win32Const.SE_UNDOCK_NAME,
                    Win32Const.SE_SYNC_AGENT_NAME,
                    Win32Const.SE_ENABLE_DELEGATION_NAME,
                    Win32Const.SE_MANAGE_VOLUME_NAME,
                    Win32Const.SE_IMPERSONATE_NAME,
                    Win32Const.SE_CREATE_GLOBAL_NAME,
                    Win32Const.SE_TRUSTED_CREDMAN_ACCESS_NAME,
                    Win32Const.SE_RELABEL_NAME,
                    Win32Const.SE_INCREASE_WORKING_SET_NAME,
                    Win32Const.SE_TIME_ZONE_NAME,
                    Win32Const.SE_CREATE_SYMBOLIC_LINK_NAME,
                    Win32Const.SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME
                };
            }
            else
            {
                privs = new string[] {
                    Win32Const.SE_DEBUG_NAME,
                    Win32Const.SE_TCB_NAME,
                    Win32Const.SE_ASSIGNPRIMARYTOKEN_NAME,
                    Win32Const.SE_IMPERSONATE_NAME
                };
            }

            Console.WriteLine("[>] Trying to create an elevated {0} token.",
                tokenType == Win32Const.TOKEN_TYPE.TokenPrimary ? "primary" : "impersonation");

            if (!Win32Api.ConvertStringSidToSid(
                Win32Const.TRUSTED_INSTALLER_RID,
                out IntPtr pTrustedInstaller))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get SID for TrustedInstaller.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            if (!CreateTokenPrivileges(
                privs,
                out Win32Struct.TOKEN_PRIVILEGES tokenPrivileges))
            {
                return IntPtr.Zero;
            }

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            IntPtr pTokenUser = Helpers.GetInformationFromToken(
                hCurrentToken,
                Win32Const.TOKEN_INFORMATION_CLASS.TokenUser);
            IntPtr pTokenGroups = Helpers.GetInformationFromToken(
                hCurrentToken,
                Win32Const.TOKEN_INFORMATION_CLASS.TokenGroups);
            IntPtr pTokenOwner = Helpers.GetInformationFromToken(
                hCurrentToken,
                Win32Const.TOKEN_INFORMATION_CLASS.TokenOwner);
            IntPtr pTokenPrimaryGroup = Helpers.GetInformationFromToken(
                hCurrentToken,
                Win32Const.TOKEN_INFORMATION_CLASS.TokenPrimaryGroup);
            IntPtr pTokenDefaultDacl = Helpers.GetInformationFromToken(
                hCurrentToken,
                Win32Const.TOKEN_INFORMATION_CLASS.TokenDefaultDacl);

            if (pTokenDefaultDacl == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get current token information.");

                return IntPtr.Zero;
            }

            var tokenUser = (Win32Struct.TOKEN_USER)Marshal.PtrToStructure(
                pTokenUser,
                typeof(Win32Struct.TOKEN_USER));
            var tokenGroups = (Win32Struct.TOKEN_GROUPS)Marshal.PtrToStructure(
                pTokenGroups,
                typeof(Win32Struct.TOKEN_GROUPS));
            var tokenOwner = (Win32Struct.TOKEN_OWNER)Marshal.PtrToStructure(
                pTokenOwner,
                typeof(Win32Struct.TOKEN_OWNER));
            var tokenPrimaryGroup = (Win32Struct.TOKEN_PRIMARY_GROUP)Marshal.PtrToStructure(
                pTokenPrimaryGroup,
                typeof(Win32Struct.TOKEN_PRIMARY_GROUP));
            var tokenDefaultDacl = (Win32Struct.TOKEN_DEFAULT_DACL)Marshal.PtrToStructure(
                pTokenDefaultDacl,
                typeof(Win32Struct.TOKEN_DEFAULT_DACL));

            tokenGroups.Groups[tokenGroups.GroupCount].Sid = pTrustedInstaller;
            tokenGroups.Groups[tokenGroups.GroupCount].Attributes = (uint)(
                Win32Const.SE_GROUP_ATTRIBUTES.SE_GROUP_OWNER |
                Win32Const.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT |
                Win32Const.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED);
            tokenGroups.GroupCount++;

            var expirationTime = new Win32Struct.LARGE_INTEGER(-1L);
            var sqos = new Win32Struct.SECURITY_QUALITY_OF_SERVICE(
                impersonationLevel,
                Win32Const.SECURITY_STATIC_TRACKING,
                0);
            var oa = new Win32Struct.OBJECT_ATTRIBUTES(string.Empty, 0);
            IntPtr pSqos = Marshal.AllocHGlobal(Marshal.SizeOf(sqos));
            Marshal.StructureToPtr(sqos, pSqos, true);
            oa.SecurityQualityOfService = pSqos;

            ntstatus = Win32Api.ZwCreateToken(
                out IntPtr hToken,
                Win32Const.TokenAccessFlags.TOKEN_ALL_ACCESS,
                ref oa,
                tokenType,
                ref authId,
                ref expirationTime,
                ref tokenUser,
                ref tokenGroups,
                ref tokenPrivileges,
                ref tokenOwner,
                ref tokenPrimaryGroup,
                ref tokenDefaultDacl,
                ref tokenSource);

            Win32Api.LocalFree(pTokenUser);
            Win32Api.LocalFree(pTokenGroups);
            Win32Api.LocalFree(pTokenOwner);
            Win32Api.LocalFree(pTokenPrimaryGroup);
            Win32Api.LocalFree(pTokenDefaultDacl);

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to create privileged token.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage((int)ntstatus, true));

                return IntPtr.Zero;
            }

            Console.WriteLine("[+] An elevated {0} token is created successfully.",
                tokenType == Win32Const.TOKEN_TYPE.TokenPrimary ? "primary" : "impersonation");

            return hToken;
        }


        public static IntPtr CreateTrustedInstallerTokenWithVirtualLogon(
            string domain,
            string username,
            int domainRid)
        {
            int error;

            Console.WriteLine("[>] Trying to generate token group information.");

            if (!Win32Api.ConvertStringSidToSid(
                Win32Const.DOMAIN_ALIAS_RID_ADMINS,
                out IntPtr pAdminGroup))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get Administrator domain SID.");
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

            var tokenGroups = new Win32Struct.TOKEN_GROUPS(2);

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

            if (!AddVirtualAccount(domain, username, domainRid))
                return IntPtr.Zero;

            Console.WriteLine("[>] Trying to logon as {0}\\{1}.", domain, username);

            if (!Win32Api.LogonUserExExW(
                username,
                domain,
                null,
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


        public static bool EnableMultiplePrivileges(
            IntPtr hToken,
            string[] privs)
        {
            StringComparison opt = StringComparison.OrdinalIgnoreCase;
            Dictionary<string, bool> results = new Dictionary<string, bool>();
            var privList = new List<string>(privs);
            var availablePrivs = GetAvailablePrivileges(hToken);
            bool isEnabled;
            bool enabledAll = true;

            foreach (var name in privList)
            {
                results.Add(name, false);
            }

            foreach (var priv in availablePrivs)
            {
                foreach (var name in privList)
                {
                    if (string.Compare(Helpers.GetPrivilegeName(priv.Key), name, opt) == 0)
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

            foreach (var result in results)
            {
                if (!result.Value)
                {
                    Console.WriteLine(
                        "[-] {0} is not available.",
                        result.Key);

                    enabledAll = false;
                }
            }

            return enabledAll;
        }


        public static Dictionary<Win32Struct.LUID, uint> GetAvailablePrivileges(
            IntPtr hToken)
        {
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
            } while (!status && (error == Win32Const.ERROR_INSUFFICIENT_BUFFER));

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


        public static bool ImpersonateAsSmss(string[] privs)
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

            if (!EnableMultiplePrivileges(hDupToken, privs))
            {
                Win32Api.CloseHandle(hDupToken);
                Win32Api.CloseHandle(hToken);

                return false;
            }

            if (!ImpersonateThreadToken(hDupToken))
            {
                Win32Api.CloseHandle(hDupToken);
                Win32Api.CloseHandle(hToken);

                return false;
            }

            Win32Api.CloseHandle(hDupToken);
            Win32Api.CloseHandle(hToken);

            return true;
        }


        public static bool ImpersonateThreadToken(IntPtr hImpersonationToken)
        {
            int error;

            Console.WriteLine("[>] Trying to impersonate thread token.");
            Console.WriteLine("    |-> Current Thread ID : {0}", Win32Api.GetCurrentThreadId());

            if (!Win32Api.ImpersonateLoggedOnUser(hImpersonationToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to impersonation.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            IntPtr pImpersonationLevel = Helpers.GetInformationFromToken(
                hCurrentToken,
                Win32Const.TOKEN_INFORMATION_CLASS.TokenImpersonationLevel);
            var impersonationLevel = (Win32Const.SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(
                pImpersonationLevel);
            Win32Api.LocalFree(pImpersonationLevel);

            if (impersonationLevel ==
                Win32Const.SECURITY_IMPERSONATION_LEVEL.SecurityIdentification)
            {
                Console.WriteLine("[-] Failed to impersonation.");
                Console.WriteLine("    |-> May not have {0}.\n", Win32Const.SE_IMPERSONATE_NAME);

                return false;
            }
            else
            {
                Console.WriteLine("[+] Impersonation is successful.");

                return true;
            }
        }


        public static bool RemoveVirtualAccount(string domain, string username)
        {
            uint ntstatus;

            if (string.IsNullOrEmpty(domain))
            {
                Console.WriteLine("[!] Domain name is required.");
                return false;
            }

            Console.WriteLine("[>] Trying to remove SID.");
            Console.WriteLine("    |-> Domain   : {0}", domain.ToLower());

            if (!string.IsNullOrEmpty(username))
                Console.WriteLine("    |-> Username : {0}", username.ToLower());

            string accountName;

            if (string.IsNullOrEmpty(username))
                accountName = domain;
            else
                accountName = string.Format("{0}\\{1}", domain.ToLower(), username.ToLower());

            string sid = Helpers.ConvertAccountNameToSidString(
                ref accountName,
                out Win32Const.SID_NAME_USE peUse);

            if (string.IsNullOrEmpty(sid))
            {
                Console.WriteLine("[-] Failed to lookup {0}.", accountName);
                return false;
            }
            else
            {
                Console.WriteLine("[*] SID : {0}.", sid);
            }

            ntstatus = Helpers.RemoveSidMapping(domain, username);

            if (ntstatus == Win32Const.STATUS_NOT_FOUND)
            {
                Console.WriteLine("[-] Requested SID is not exist.\n");

                return false;
            }

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                Console.WriteLine("[!] Unexpected error.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage((int)ntstatus, true));
                
                return false;
            }

            Console.WriteLine("[+] Requested SID is removed successfully.\n");

            return true;
        }
    }
}
