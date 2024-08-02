using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
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


        public static IntPtr CreateTrustedInstallerToken(
            TOKEN_TYPE tokenType,
            in List<string> extraGroupSids)
        {
            IntPtr hToken;
            IntPtr pTokenGroups;
            int nOffset;
            int nDosErrorCode;
            int nPrivilegeCount = 0;
            var nPrivilegesOffset = Marshal.OffsetOf(typeof(TOKEN_PRIVILEGES), "Privileges").ToInt32();
            var nGroupOffset = Marshal.OffsetOf(typeof(TOKEN_GROUPS), "Groups").ToInt32();
            var nPrivilegeSize = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
            var nGroupSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
            var pTokenPrivileges = Marshal.AllocHGlobal(nPrivilegesOffset + nPrivilegeSize * 36);
            var sqos = new SECURITY_QUALITY_OF_SERVICE
            {
                Length = Marshal.SizeOf(typeof(SECURITY_QUALITY_OF_SERVICE)),
                ImpersonationLevel = (tokenType == TOKEN_TYPE.Primary) ? SECURITY_IMPERSONATION_LEVEL.Anonymous : SECURITY_IMPERSONATION_LEVEL.Impersonation,
                ContextTrackingMode = SECURITY_CONTEXT_TRACKING_MODE.StaticTracking,
                EffectiveOnly = BOOLEAN.FALSE
            };
            var privAttributes = (int)(SE_PRIVILEGE_ATTRIBUTES.Enabled | SE_PRIVILEGE_ATTRIBUTES.EnabledByDefault);
            var pSqos = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SECURITY_QUALITY_OF_SERVICE)));
            var groupAttributes = SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault | SE_GROUP_ATTRIBUTES.Mandatory;
            var logonSessionSid = Helpers.GetCurrentLogonSessionSid();
            var groups = new Dictionary<string, SE_GROUP_ATTRIBUTES>
            {
                { "S-1-1-0", groupAttributes }, // Everyone
                { "S-1-2-0", groupAttributes }, // LOCAL
                { "S-1-2-1", groupAttributes }, // CONSOLE LOGON
                { "S-1-5-6", groupAttributes }, // NT AUTHORITY\SERVICE
                { "S-1-5-11", groupAttributes }, // NT AUTHORITY\Authenticated Users
                { "S-1-5-18", groupAttributes }, // NT AUTHORITY\SYSTEM
                { "S-1-5-32-544", groupAttributes | SE_GROUP_ATTRIBUTES.Owner }, // BUILTIN\Administrators
                { "S-1-5-32-545", groupAttributes }, // BUILTIN\Users
                { "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", groupAttributes }, // NT SERVICE\TrustedInstaller
                { "S-1-16-16384", SE_GROUP_ATTRIBUTES.Integrity | SE_GROUP_ATTRIBUTES.IntegrityEnabled } // NT SERVICE\TrustedInstaller
            };
            var aces = new Dictionary<string, ACCESS_MASK>
            {
                { "S-1-5-18", ACCESS_MASK.GENERIC_ALL },
                { "S-1-5-32-544", ACCESS_MASK.GENERIC_EXECUTE | ACCESS_MASK.GENERIC_READ | ACCESS_MASK.READ_CONTROL }
            };
            var nAceSize = Marshal.OffsetOf(typeof(ACCESS_ALLOWED_ACE), "SidStart").ToInt32() + 0x10;
            var pDefaultDacl = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ACL)) + (nAceSize * aces.Count));
            var acl = new ACL
            {
                AclRevision = ACL_REVISION.ACL_REVISION,
                AclSize = (short)(Marshal.SizeOf(typeof(ACL)) + (nAceSize * aces.Count)),
                AceCount = (short)aces.Count
            };
            var groupSids = new Dictionary<string, IntPtr>();
            Marshal.StructureToPtr(sqos, pSqos, true);

            if (!string.IsNullOrEmpty(logonSessionSid))
                groups.Add(logonSessionSid, groupAttributes | SE_GROUP_ATTRIBUTES.LogonId);

            foreach (var sid in extraGroupSids)
            {
                if (Regex.IsMatch(sid, @"S(-\d){2,}", RegexOptions.IgnoreCase))
                    groups.Add(sid.ToUpper(), groupAttributes);
            }

            pTokenGroups = Marshal.AllocHGlobal(nGroupOffset + (nGroupSize * groups.Count));
            nOffset = nGroupOffset;

            foreach (var group in groups)
            {
                groupSids.Add(group.Key, Helpers.ConvertStringSidToSid(group.Key, out int _));
                Marshal.WriteIntPtr(pTokenGroups, nOffset, groupSids[group.Key]);
                Marshal.WriteInt32(pTokenGroups, nOffset + IntPtr.Size, (int)group.Value);
                nOffset += nGroupSize;
            }

            Marshal.WriteInt32(pTokenGroups, groups.Count);
            nOffset = nPrivilegesOffset;

            for (var id = SE_PRIVILEGE_ID.SeCreateTokenPrivilege; id < SE_PRIVILEGE_ID.MaximumCount; id++)
            {
                Marshal.WriteInt64(pTokenPrivileges, nOffset, (long)id);
                Marshal.WriteInt32(pTokenPrivileges, nOffset + 8, privAttributes);
                nOffset += nPrivilegeSize;
                nPrivilegeCount++;
            }

            Marshal.WriteInt32(pTokenPrivileges, nPrivilegeCount);
            Marshal.StructureToPtr(acl, pDefaultDacl, true);
            nOffset = Marshal.SizeOf(typeof(ACL));

            foreach (var ace in aces)
            {
                IntPtr pSid = groupSids[ace.Key];
                var entry = new ACCESS_ALLOWED_ACE
                {
                    Header = new ACE_HEADER
                    {
                        AceType = ACE_TYPE.AccessAllowed,
                        AceFlags = ACE_FLAGS.None,
                        AceSize = (short)nAceSize
                    },
                    Mask = ace.Value
                };
                int nSidSize = 8 + (Marshal.ReadByte(pSid, 1) * 4);

                if (Environment.Is64BitProcess)
                    Marshal.StructureToPtr(entry, new IntPtr(pDefaultDacl.ToInt64() + nOffset), true);
                else
                    Marshal.StructureToPtr(entry, new IntPtr(pDefaultDacl.ToInt32() + nOffset), true);

                for (var idx = 0; idx < nSidSize; idx++)
                {
                    var oft = Marshal.OffsetOf(typeof(ACCESS_ALLOWED_ACE), "SidStart").ToInt32() + idx;
                    Marshal.WriteByte(pDefaultDacl, nOffset + oft, Marshal.ReadByte(pSid, idx));
                }

                nOffset += nAceSize;
            }

            do
            {
                var objectAttributes = new OBJECT_ATTRIBUTES
                {
                    Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                    SecurityQualityOfService = pSqos
                };
                var authId = LUID.FromInt64(0x3e7); // SYSTEM_LUID
                var expirationTime = new LARGE_INTEGER(-1L);
                var tokenUser = new TOKEN_USER {
                    User = new SID_AND_ATTRIBUTES { Sid = groupSids["S-1-5-18"] }
                };
                var tokenOwner = new TOKEN_OWNER { Owner = groupSids["S-1-5-18"] };
                var tokenPrimaryGroup = new TOKEN_PRIMARY_GROUP { PrimaryGroup = groupSids["S-1-5-18"] };
                var tokenDefaultDacl = new TOKEN_DEFAULT_DACL { DefaultDacl = pDefaultDacl };
                var tokenSource = new TOKEN_SOURCE("*SYSTEM*");
                NTSTATUS ntstatus = NativeMethods.NtCreateToken(
                    out hToken,
                    ACCESS_MASK.TOKEN_ALL_ACCESS,
                    in objectAttributes,
                    tokenType,
                    in authId,
                    in expirationTime,
                    in tokenUser,
                    pTokenGroups,
                    pTokenPrivileges,
                    in tokenOwner,
                    in tokenPrimaryGroup,
                    in tokenDefaultDacl,
                    in tokenSource);
                nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    hToken = IntPtr.Zero;
            } while (false);

            foreach (var pSid in groupSids.Values)
                Marshal.FreeHGlobal(pSid);

            Marshal.FreeHGlobal(pSqos);
            Marshal.FreeHGlobal(pDefaultDacl);
            Marshal.FreeHGlobal(pTokenGroups);
            Marshal.FreeHGlobal(pTokenPrivileges);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

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

            if (!NativeMethods.ConvertStringSidToSid("S-1-5-32-544", out IntPtr pAdminGroup))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get Administrator domain SID.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                
                return IntPtr.Zero;
            }

            if (!NativeMethods.ConvertStringSidToSid(
                "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
                out IntPtr pTrustedInstaller))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get Trusted Installer SID.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                
                return IntPtr.Zero;
            }

            if (!NativeMethods.ConvertStringSidToSid("S-1-16-16384", out IntPtr pSystemIntegrity))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get System Integrity Level SID.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                
                return IntPtr.Zero;
            }

            var tokenGroups = new TOKEN_GROUPS(2);

            tokenGroups.Groups[0].Sid = pAdminGroup;
            tokenGroups.Groups[0].Attributes = (uint)(
                SE_GROUP_ATTRIBUTES.Enabled |
                SE_GROUP_ATTRIBUTES.EnabledByDefault |
                SE_GROUP_ATTRIBUTES.Mandatory);
            tokenGroups.Groups[1].Sid = pTrustedInstaller;
            tokenGroups.Groups[1].Attributes = (uint)(
                SE_GROUP_ATTRIBUTES.Enabled |
                SE_GROUP_ATTRIBUTES.EnabledByDefault |
                SE_GROUP_ATTRIBUTES.Owner);

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
                        SE_GROUP_ATTRIBUTES.Mandatory |
                        SE_GROUP_ATTRIBUTES.Enabled);
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
                SE_GROUP_ATTRIBUTES.Integrity |
                SE_GROUP_ATTRIBUTES.IntegrityEnabled);

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


        public static bool ImpersonateAsSmss(in List<SE_PRIVILEGE_ID> privs)
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
                    SECURITY_IMPERSONATION_LEVEL.Impersonation,
                    TOKEN_TYPE.Primary,
                    out IntPtr hDupToken);
                NativeMethods.CloseHandle(hToken);

                if (!status)
                    break;

                Helpers.EnableTokenPrivileges(hDupToken, privs, out Dictionary<SE_PRIVILEGE_ID, bool> _);

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

                    if (level == SECURITY_IMPERSONATION_LEVEL.Impersonation)
                        status = true;
                    else if (level == SECURITY_IMPERSONATION_LEVEL.Delegation)
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
