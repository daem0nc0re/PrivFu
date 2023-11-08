using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using TrustExec.Interop;

namespace TrustExec.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static bool AddVirtualAccount(string domain, string username, int domainRid)
        {
            int error;
            NTSTATUS ntstatus;
            var domainSid = string.Format("S-1-5-{0}", domainRid);
            var userSid = string.Format("S-1-5-{0}-110", domainRid);

            if (string.IsNullOrEmpty(domain) || string.IsNullOrEmpty(username))
            {
                Console.WriteLine("[!] Domain name and username are required.");
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
            NativeMethods.LocalFree(pSidDomain);

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


        public static bool CreateTokenAssignedProcess(IntPtr hToken, string command)
        {
            var startupInfo = new STARTUPINFO
            {
                cb = Marshal.SizeOf(typeof(STARTUPINFO)),
                lpDesktop = @"Winsta0\Default"
            };
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
                in startupInfo,
                out PROCESS_INFORMATION processInformation);

            if (status)
            {
                NativeMethods.WaitForSingleObject(processInformation.hProcess, uint.MaxValue);
                NativeMethods.CloseHandle(processInformation.hThread);
                NativeMethods.CloseHandle(processInformation.hProcess);
            }

            return status;
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
                    SE_PRIVILEGE_ATTRIBUTES.ENABLED |
                    SE_PRIVILEGE_ATTRIBUTES.ENABLED_BY_DEFAULT);
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
            NTSTATUS ntstatus;
            LUID authId = Win32Consts.SYSTEM_LUID;
            var tokenSource = new TOKEN_SOURCE("*SYSTEM*");
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

            NativeMethods.ConvertStringSidToSid(
                Win32Consts.TRUSTED_INSTALLER_RID,
                out IntPtr pTrustedInstaller);

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


        public static bool EnableAllTokenPrivileges(
            IntPtr hToken,
            out Dictionary<string, bool> adjustedPrivs)
        {
            bool allEnabled;

            do
            {
                var privsToEnable = new List<string>();
                allEnabled = Helpers.GetTokenPrivileges(
                    hToken,
                    out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                if (!allEnabled)
                {
                    adjustedPrivs = new Dictionary<string, bool>();
                    break;
                }

                foreach (var privName in availablePrivs.Keys)
                    privsToEnable.Add(privName);

                allEnabled = EnableTokenPrivileges(hToken, privsToEnable, out adjustedPrivs);
            } while (false);

            return allEnabled;
        }


        public static bool EnableTokenPrivileges(
            IntPtr hToken,
            List<string> requiredPrivs,
            out Dictionary<string, bool> adjustedPrivs)
        {
            var allEnabled = true;
            adjustedPrivs = new Dictionary<string, bool>();

            do
            {
                if (requiredPrivs.Count == 0)
                    break;

                allEnabled = Helpers.GetTokenPrivileges(
                    hToken,
                    out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                if (!allEnabled)
                    break;

                foreach (var priv in requiredPrivs)
                {
                    adjustedPrivs.Add(priv, false);

                    foreach (var available in availablePrivs)
                    {
                        if (Helpers.CompareIgnoreCase(available.Key, priv))
                        {
                            if ((available.Value & SE_PRIVILEGE_ATTRIBUTES.ENABLED) != 0)
                            {
                                adjustedPrivs[priv] = true;
                            }
                            else
                            {
                                IntPtr pTokenPrivileges = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));
                                var tokenPrivileges = new TOKEN_PRIVILEGES(1);

                                if (NativeMethods.LookupPrivilegeValue(
                                    null,
                                    priv,
                                    out tokenPrivileges.Privileges[0].Luid))
                                {
                                    tokenPrivileges.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.ENABLED;
                                    Marshal.StructureToPtr(tokenPrivileges, pTokenPrivileges, true);

                                    adjustedPrivs[priv] = NativeMethods.AdjustTokenPrivileges(
                                        hToken,
                                        false,
                                        pTokenPrivileges,
                                        Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)),
                                        IntPtr.Zero,
                                        out int _);
                                    adjustedPrivs[priv] = (adjustedPrivs[priv] && (Marshal.GetLastWin32Error() == 0));
                                }

                                Marshal.FreeHGlobal(pTokenPrivileges);
                            }

                            break;
                        }
                    }

                    if (!adjustedPrivs[priv])
                        allEnabled = false;
                }
            } while (false);

            return allEnabled;
        }


        public static bool ImpersonateAsSmss(List<string> privs)
        {
            int smss;
            var status = false;

            try
            {
                smss = (Process.GetProcessesByName("smss")[0]).Id;
            }
            catch
            {
                return status;
            }

            do
            {
                IntPtr hProcess = NativeMethods.OpenProcess(
                    ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                    true,
                    smss);

                if (hProcess == IntPtr.Zero)
                    break;

                status = NativeMethods.OpenProcessToken(
                    hProcess,
                    TokenAccessFlags.TOKEN_DUPLICATE,
                    out IntPtr hToken);
                NativeMethods.CloseHandle(hProcess);

                if (!status)
                    break;

                status = NativeMethods.DuplicateTokenEx(
                    hToken,
                    TokenAccessFlags.MAXIMUM_ALLOWED,
                    IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    TOKEN_TYPE.TokenPrimary,
                    out IntPtr hDupToken);
                NativeMethods.CloseHandle(hToken);

                if (!status)
                    break;

                EnableTokenPrivileges(hDupToken, privs, out Dictionary<string, bool> _);

                status = ImpersonateThreadToken(hDupToken);
                NativeMethods.CloseHandle(hDupToken);
            } while (false);

            return status;
        }


        public static bool ImpersonateThreadToken(IntPtr hImpersonationToken)
        {
            IntPtr pImpersonationLevel = Marshal.AllocHGlobal(4);
            var status = false;

            if (NativeMethods.ImpersonateLoggedOnUser(hImpersonationToken))
            {
                NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                    WindowsIdentity.GetCurrent().Token,
                    TOKEN_INFORMATION_CLASS.TokenImpersonationLevel,
                    pImpersonationLevel,
                    4u,
                    out uint _);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                {
                    var level = (SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(pImpersonationLevel);

                    if (level == SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation)
                        status = true;
                    else if (level == SECURITY_IMPERSONATION_LEVEL.SecurityDelegation)
                        status = true;
                    else
                        status = false;
                }
            }

            Marshal.FreeHGlobal(pImpersonationLevel);

            return status;
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

            bool status = Helpers.ConvertAccountNameToSidString(
                ref username,
                ref domain,
                out string sid,
                out SID_NAME_USE _);

            if (string.IsNullOrEmpty(sid) || !status)
            {
                Console.WriteLine("[-] Failed to lookup.");
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
