using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using TrustExec.Interop;

namespace TrustExec.Library
{
    internal class Utilities
    {
        public static bool AddVirtualAccount(
            string domain,
            string username,
            int domainRid)
        {
            int error;
            int ntstatus;
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

            if (!NativeMethods.ConvertStringSidToSid(
                domainSid,
                out IntPtr pSidDomain))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to initialize virtual domain SID.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                
                return false;
            }

            if (!NativeMethods.ConvertStringSidToSid(
                userSid,
                out IntPtr pSidUser))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to initialize virtual domain SID.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                
                return false;
            }

            ntstatus = Helpers.AddSidMapping(domain, null, pSidDomain);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                Helpers.AddSidMapping(domain, username, pSidUser);
                Console.WriteLine("[+] Added virtual domain and user.");
            }
            else if (ntstatus == Win32Consts.STATUS_INVALID_PARAMETER)
            {
                Console.WriteLine("[*] {0} or {1} maybe already exists or invalid.", domainSid, domain);
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
            var startupInfo = new STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(startupInfo);
            startupInfo.lpDesktop = @"Winsta0\Default";

            Console.WriteLine("[>] Trying to create a token assigned process.\n");

            bool status = NativeMethods.CreateProcessAsUser(
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
                out PROCESS_INFORMATION processInformation);

            if (!status)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to create new process.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                
                return false;
            }

            NativeMethods.WaitForSingleObject(processInformation.hProcess, uint.MaxValue);
            NativeMethods.CloseHandle(processInformation.hThread);
            NativeMethods.CloseHandle(processInformation.hProcess);

            return true;
        }


        public static bool CreateTokenPrivileges(
            string[] privs,
            out TOKEN_PRIVILEGES tokenPrivileges)
        {
            int error;
            int sizeOfStruct = Marshal.SizeOf(typeof(TOKEN_PRIVILEGES));
            IntPtr pPrivileges = Marshal.AllocHGlobal(sizeOfStruct);

            tokenPrivileges = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(
                pPrivileges,
                typeof(TOKEN_PRIVILEGES));
            tokenPrivileges.PrivilegeCount = privs.Length;

            for (var idx = 0; idx < tokenPrivileges.PrivilegeCount; idx++)
            {
                if (!NativeMethods.LookupPrivilegeValue(
                    null,
                    privs[idx],
                    out LUID luid))
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to lookup LUID for {0}.", privs[idx]);
                    Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                    return false;
                }

                tokenPrivileges.Privileges[idx].Attributes = (uint)(
                    SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED |
                    SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED_BY_DEFAULT);
                tokenPrivileges.Privileges[idx].Luid = luid;
            }

            return true;
        }


        public static IntPtr CreateTrustedInstallerToken(
            TOKEN_TYPE tokenType,
            SECURITY_IMPERSONATION_LEVEL impersonationLevel,
            string[] extraSidsArray,
            bool full)
        {
            int error;
            int ntstatus;
            LUID authId = Win32Consts.SYSTEM_LUID;
            var tokenSource = new TOKEN_SOURCE("*SYSTEM*");
            tokenSource.SourceIdentifier.HighPart = 0;
            tokenSource.SourceIdentifier.LowPart = 0;
            string[] privs;

            if (full)
            {
                privs = new string[] {
                    Win32Consts.SE_CREATE_TOKEN_NAME,
                    Win32Consts.SE_ASSIGNPRIMARYTOKEN_NAME,
                    Win32Consts.SE_LOCK_MEMORY_NAME,
                    Win32Consts.SE_INCREASE_QUOTA_NAME,
                    Win32Consts.SE_MACHINE_ACCOUNT_NAME,
                    Win32Consts.SE_TCB_NAME,
                    Win32Consts.SE_SECURITY_NAME,
                    Win32Consts.SE_TAKE_OWNERSHIP_NAME,
                    Win32Consts.SE_LOAD_DRIVER_NAME,
                    Win32Consts.SE_SYSTEM_PROFILE_NAME,
                    Win32Consts.SE_SYSTEMTIME_NAME,
                    Win32Consts.SE_PROFILE_SINGLE_PROCESS_NAME,
                    Win32Consts.SE_INCREASE_BASE_PRIORITY_NAME,
                    Win32Consts.SE_CREATE_PAGEFILE_NAME,
                    Win32Consts.SE_CREATE_PERMANENT_NAME,
                    Win32Consts.SE_BACKUP_NAME,
                    Win32Consts.SE_RESTORE_NAME,
                    Win32Consts.SE_SHUTDOWN_NAME,
                    Win32Consts.SE_DEBUG_NAME,
                    Win32Consts.SE_AUDIT_NAME,
                    Win32Consts.SE_SYSTEM_ENVIRONMENT_NAME,
                    Win32Consts.SE_CHANGE_NOTIFY_NAME,
                    Win32Consts.SE_REMOTE_SHUTDOWN_NAME,
                    Win32Consts.SE_UNDOCK_NAME,
                    Win32Consts.SE_SYNC_AGENT_NAME,
                    Win32Consts.SE_ENABLE_DELEGATION_NAME,
                    Win32Consts.SE_MANAGE_VOLUME_NAME,
                    Win32Consts.SE_IMPERSONATE_NAME,
                    Win32Consts.SE_CREATE_GLOBAL_NAME,
                    Win32Consts.SE_TRUSTED_CREDMAN_ACCESS_NAME,
                    Win32Consts.SE_RELABEL_NAME,
                    Win32Consts.SE_INCREASE_WORKING_SET_NAME,
                    Win32Consts.SE_TIME_ZONE_NAME,
                    Win32Consts.SE_CREATE_SYMBOLIC_LINK_NAME,
                    Win32Consts.SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME
                };
            }
            else
            {
                privs = new string[] {
                    Win32Consts.SE_DEBUG_NAME,
                    Win32Consts.SE_TCB_NAME,
                    Win32Consts.SE_ASSIGNPRIMARYTOKEN_NAME,
                    Win32Consts.SE_IMPERSONATE_NAME
                };
            }

            Console.WriteLine("[>] Trying to create an elevated {0} token.",
                tokenType == TOKEN_TYPE.TokenPrimary ? "primary" : "impersonation");

            if (!NativeMethods.ConvertStringSidToSid(
                Win32Consts.TRUSTED_INSTALLER_RID,
                out IntPtr pTrustedInstaller))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get SID for TrustedInstaller.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            if (!CreateTokenPrivileges(
                privs,
                out TOKEN_PRIVILEGES tokenPrivileges))
            {
                return IntPtr.Zero;
            }

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            IntPtr pTokenUser = Helpers.GetInformationFromToken(
                hCurrentToken,
                TOKEN_INFORMATION_CLASS.TokenUser);
            IntPtr pTokenGroups = Helpers.GetInformationFromToken(
                hCurrentToken,
                TOKEN_INFORMATION_CLASS.TokenGroups);
            IntPtr pTokenOwner = Helpers.GetInformationFromToken(
                hCurrentToken,
                TOKEN_INFORMATION_CLASS.TokenOwner);
            IntPtr pTokenPrimaryGroup = Helpers.GetInformationFromToken(
                hCurrentToken,
                TOKEN_INFORMATION_CLASS.TokenPrimaryGroup);
            IntPtr pTokenDefaultDacl = Helpers.GetInformationFromToken(
                hCurrentToken,
                TOKEN_INFORMATION_CLASS.TokenDefaultDacl);

            if (pTokenDefaultDacl == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get current token information.");

                return IntPtr.Zero;
            }

            var tokenUser = (TOKEN_USER)Marshal.PtrToStructure(
                pTokenUser,
                typeof(TOKEN_USER));
            var tokenGroups = (TOKEN_GROUPS)Marshal.PtrToStructure(
                pTokenGroups,
                typeof(TOKEN_GROUPS));
            var tokenOwner = (TOKEN_OWNER)Marshal.PtrToStructure(
                pTokenOwner,
                typeof(TOKEN_OWNER));
            var tokenPrimaryGroup = (TOKEN_PRIMARY_GROUP)Marshal.PtrToStructure(
                pTokenPrimaryGroup,
                typeof(TOKEN_PRIMARY_GROUP));
            var tokenDefaultDacl = (TOKEN_DEFAULT_DACL)Marshal.PtrToStructure(
                pTokenDefaultDacl,
                typeof(TOKEN_DEFAULT_DACL));

            tokenGroups.Groups[tokenGroups.GroupCount].Sid = pTrustedInstaller;
            tokenGroups.Groups[tokenGroups.GroupCount].Attributes = (uint)(
                SE_GROUP_ATTRIBUTES.SE_GROUP_OWNER |
                SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT |
                SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED);
            tokenGroups.GroupCount++;

            for (var idx = 0; idx < extraSidsArray.Length; idx++)
            {
                if (tokenGroups.GroupCount >= 32)
                {
                    Console.WriteLine("[!] Token groups count reached maximum. {0} is ignored.", extraSidsArray[idx]);
                    continue;
                }

                if (NativeMethods.ConvertStringSidToSid(
                    extraSidsArray[idx],
                    out IntPtr pExtraSid))
                {
                    tokenGroups.Groups[tokenGroups.GroupCount].Sid = pExtraSid;
                    tokenGroups.Groups[tokenGroups.GroupCount].Attributes = (uint)(
                        SE_GROUP_ATTRIBUTES.SE_GROUP_MANDATORY |
                        SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED);
                    tokenGroups.GroupCount++;
                }
                else
                {
                    Console.WriteLine("[-] Failed to add {0}.", extraSidsArray[idx]);
                }
            }

            var expirationTime = new LARGE_INTEGER(-1L);
            var sqos = new SECURITY_QUALITY_OF_SERVICE(
                impersonationLevel,
                Win32Consts.SECURITY_STATIC_TRACKING,
                0);
            var oa = new OBJECT_ATTRIBUTES(string.Empty, 0);
            IntPtr pSqos = Marshal.AllocHGlobal(Marshal.SizeOf(sqos));
            Marshal.StructureToPtr(sqos, pSqos, true);
            oa.SecurityQualityOfService = pSqos;

            ntstatus = NativeMethods.ZwCreateToken(
                out IntPtr hToken,
                TokenAccessFlags.TOKEN_ALL_ACCESS,
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

            NativeMethods.LocalFree(pTokenUser);
            NativeMethods.LocalFree(pTokenGroups);
            NativeMethods.LocalFree(pTokenOwner);
            NativeMethods.LocalFree(pTokenPrimaryGroup);
            NativeMethods.LocalFree(pTokenDefaultDacl);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to create privileged token.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(ntstatus, true));

                return IntPtr.Zero;
            }

            Console.WriteLine("[+] An elevated {0} token is created successfully.",
                tokenType == TOKEN_TYPE.TokenPrimary ? "primary" : "impersonation");

            return hToken;
        }


        public static IntPtr CreateTrustedInstallerTokenWithVirtualLogon(
            string domain,
            string username,
            int domainRid,
            string[] extraSidsArray)
        {
            int error;

            Console.WriteLine("[>] Trying to generate token group information.");

            if (!NativeMethods.ConvertStringSidToSid(
                Win32Consts.DOMAIN_ALIAS_RID_ADMINS,
                out IntPtr pAdminGroup))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get Administrator domain SID.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                
                return IntPtr.Zero;
            }

            if (!NativeMethods.ConvertStringSidToSid(
                Win32Consts.TRUSTED_INSTALLER_RID,
                out IntPtr pTrustedInstaller))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get Trusted Installer SID.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                
                return IntPtr.Zero;
            }

            if (!NativeMethods.ConvertStringSidToSid(
                Win32Consts.SYSTEM_MANDATORY_LEVEL,
                out IntPtr pSystemIntegrity))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get System Integrity Level SID.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                
                return IntPtr.Zero;
            }

            var tokenGroups = new TOKEN_GROUPS(2);

            tokenGroups.Groups[0].Sid = pAdminGroup;
            tokenGroups.Groups[0].Attributes = (uint)(
                SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT |
                SE_GROUP_ATTRIBUTES.SE_GROUP_MANDATORY);
            tokenGroups.Groups[1].Sid = pTrustedInstaller;
            tokenGroups.Groups[1].Attributes = (uint)(
                SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT |
                SE_GROUP_ATTRIBUTES.SE_GROUP_OWNER);

            for (var idx = 0; idx < extraSidsArray.Length; idx++)
            {
                if (tokenGroups.GroupCount >= 32)
                {
                    Console.WriteLine("[!] Token groups count reached maximum. {0} is ignored.", extraSidsArray[idx]);
                    continue;
                }

                if (NativeMethods.ConvertStringSidToSid(
                    extraSidsArray[idx],
                    out IntPtr pExtraSid))
                {
                    tokenGroups.Groups[tokenGroups.GroupCount].Sid = pExtraSid;
                    tokenGroups.Groups[tokenGroups.GroupCount].Attributes = (uint)(
                        SE_GROUP_ATTRIBUTES.SE_GROUP_MANDATORY |
                        SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED);
                    tokenGroups.GroupCount++;
                }
                else
                {
                    Console.WriteLine("[-] Failed to add {0}.", extraSidsArray[idx]);
                }
            }

            var pTokenGroups = Marshal.AllocHGlobal(Marshal.SizeOf(tokenGroups));
            Marshal.StructureToPtr(tokenGroups, pTokenGroups, true);

            if (!AddVirtualAccount(domain, username, domainRid))
                return IntPtr.Zero;

            Console.WriteLine(@"[>] Trying to logon as {0}\{1}.", domain, username);

            if (!NativeMethods.LogonUserExExW(
                username,
                domain,
                null,
                Win32Consts.LOGON32_LOGON_INTERACTIVE,
                Win32Consts.LOGON32_PROVIDER_VIRTUAL,
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
                TOKEN_INFORMATION_CLASS.TokenLinkedToken);

            if (pLinkedToken == IntPtr.Zero)
                return IntPtr.Zero;

            var linkedToken = (TOKEN_LINKED_TOKEN)Marshal.PtrToStructure(
                pLinkedToken,
                typeof(TOKEN_LINKED_TOKEN));

            hToken = linkedToken.LinkedToken;

            var mandatoryLabel = new TOKEN_MANDATORY_LABEL();
            mandatoryLabel.Label.Sid = pSystemIntegrity;
            mandatoryLabel.Label.Attributes = (uint)(
                SE_GROUP_ATTRIBUTES.SE_GROUP_INTEGRITY |
                SE_GROUP_ATTRIBUTES.SE_GROUP_INTEGRITY_ENABLED);

            IntPtr pMandatoryLabel = Marshal.AllocHGlobal(Marshal.SizeOf(mandatoryLabel));
            Marshal.StructureToPtr(mandatoryLabel, pMandatoryLabel, true);

            if (!NativeMethods.SetTokenInformation(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
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
            Dictionary<LUID, uint> privs = GetAvailablePrivileges(hToken);
            bool isEnabled;

            foreach (var priv in privs)
            {
                isEnabled = ((priv.Value & (uint)SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED) != 0);

                if (!isEnabled)
                {
                    EnableSinglePrivilege(hToken, priv.Key);
                }
            }
        }


        public static bool EnableSinglePrivilege(IntPtr hToken, LUID priv)
        {
            int error;
            var tp = new TOKEN_PRIVILEGES(1);
            tp.Privileges[0].Luid = priv;
            tp.Privileges[0].Attributes = (uint)SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED;

            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(tp));
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            if (!NativeMethods.AdjustTokenPrivileges(
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

            // Console.WriteLine("[+] {0} is enabled successfully.", Helpers.GetPrivilegeName(priv));

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
                        isEnabled = ((priv.Value & (uint)SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED) != 0);

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


        public static Dictionary<LUID, uint> GetAvailablePrivileges(
            IntPtr hToken)
        {
            int error;
            bool status;
            int bufferLength = Marshal.SizeOf(typeof(TOKEN_PRIVILEGES));
            var availablePrivs = new Dictionary<LUID, uint>();
            IntPtr pTokenPrivileges;

            do
            {
                pTokenPrivileges = Marshal.AllocHGlobal(bufferLength);
                Helpers.ZeroMemory(pTokenPrivileges, bufferLength);

                status = NativeMethods.GetTokenInformation(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenPrivileges,
                    pTokenPrivileges,
                    bufferLength,
                    out bufferLength);
                error = Marshal.GetLastWin32Error();

                if (!status)
                    Marshal.FreeHGlobal(pTokenPrivileges);
            } while (!status && (error == Win32Consts.ERROR_INSUFFICIENT_BUFFER));

            if (!status)
                return availablePrivs;

            int privCount = Marshal.ReadInt32(pTokenPrivileges);
            IntPtr buffer = new IntPtr(pTokenPrivileges.ToInt64() + Marshal.SizeOf(privCount));

            for (var count = 0; count < privCount; count++)
            {
                var luidAndAttr = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                    buffer,
                    typeof(LUID_AND_ATTRIBUTES));

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

            IntPtr hProcess = NativeMethods.OpenProcess(
                ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                true,
                smss);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get handle to smss.exe process.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                
                return false;
            }

            if (!NativeMethods.OpenProcessToken(
                hProcess,
                TokenAccessFlags.TOKEN_DUPLICATE,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get handle to smss.exe process token.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                NativeMethods.CloseHandle(hProcess);

                return false;
            }

            NativeMethods.CloseHandle(hProcess);

            if (!NativeMethods.DuplicateTokenEx(
                hToken,
                TokenAccessFlags.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                TOKEN_TYPE.TokenPrimary,
                out IntPtr hDupToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to duplicate smss.exe process token.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                NativeMethods.CloseHandle(hToken);
                
                return false;
            }

            if (!EnableMultiplePrivileges(hDupToken, privs))
            {
                NativeMethods.CloseHandle(hDupToken);
                NativeMethods.CloseHandle(hToken);

                return false;
            }

            if (!ImpersonateThreadToken(hDupToken))
            {
                NativeMethods.CloseHandle(hDupToken);
                NativeMethods.CloseHandle(hToken);

                return false;
            }

            NativeMethods.CloseHandle(hDupToken);
            NativeMethods.CloseHandle(hToken);

            return true;
        }


        public static bool ImpersonateThreadToken(IntPtr hImpersonationToken)
        {
            int error;

            Console.WriteLine("[>] Trying to impersonate thread token.");
            Console.WriteLine("    |-> Current Thread ID : {0}", NativeMethods.GetCurrentThreadId());

            if (!NativeMethods.ImpersonateLoggedOnUser(hImpersonationToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to impersonation.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            IntPtr pImpersonationLevel = Helpers.GetInformationFromToken(
                hCurrentToken,
                TOKEN_INFORMATION_CLASS.TokenImpersonationLevel);
            var impersonationLevel = (SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(
                pImpersonationLevel);
            NativeMethods.LocalFree(pImpersonationLevel);

            if (impersonationLevel ==
                SECURITY_IMPERSONATION_LEVEL.SecurityIdentification)
            {
                Console.WriteLine("[-] Failed to impersonation.");
                Console.WriteLine("    |-> May not have {0}.\n", Win32Consts.SE_IMPERSONATE_NAME);

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
            int ntstatus;

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
                accountName = string.Format(@"{0}\{1}", domain.ToLower(), username.ToLower());

            string sid = Helpers.ConvertAccountNameToSidString(
                ref accountName,
                out SID_NAME_USE peUse);

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

            if (ntstatus == Win32Consts.STATUS_NOT_FOUND)
            {
                Console.WriteLine("[-] Requested SID is not exist.\n");

                return false;
            }

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
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
