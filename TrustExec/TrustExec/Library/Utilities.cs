using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using TrustExec.Interop;

namespace TrustExec.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static bool CreateTokenAssignedSuspendedProcess(
            IntPtr hToken,
            string command,
            ref bool bNewConsole,
            out PROCESS_INFORMATION processInfo)
        {
            bool bSuccess;
            var startupInfo = new STARTUPINFO
            {
                cb = Marshal.SizeOf(typeof(STARTUPINFO)),
                wShowWindow = bNewConsole ? SHOW_WINDOW_FLAGS.SW_SHOW : SHOW_WINDOW_FLAGS.SW_HIDE,
                lpDesktop = @"Winsta0\Default"
            };
            var flags = PROCESS_CREATION_FLAGS.CREATE_BREAKAWAY_FROM_JOB | PROCESS_CREATION_FLAGS.CREATE_SUSPENDED;

            if (bNewConsole)
                flags |= PROCESS_CREATION_FLAGS.CREATE_NEW_CONSOLE;

            bSuccess = NativeMethods.CreateProcessAsUser(
                hToken,
                null,
                command,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                flags,
                IntPtr.Zero,
                Environment.CurrentDirectory,
                in startupInfo,
                out processInfo);

            if (!bSuccess)
            {
                bSuccess = NativeMethods.CreateProcessWithTokenW(
                    hToken,
                    LOGON_FLAGS.NONE,
                    null,
                    command,
                    flags,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfo,
                    out processInfo);
                bNewConsole = bSuccess;
            }

            return bSuccess;
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
            var groupAttributes = SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault;
            var logonSessionSid = Helpers.GetCurrentLogonSessionSid();
            var tokenGroups = new Dictionary<string, SE_GROUP_ATTRIBUTES>
            {
                { "S-1-1-0", groupAttributes | SE_GROUP_ATTRIBUTES.Mandatory }, // Everyone
                { "S-1-2-0", groupAttributes | SE_GROUP_ATTRIBUTES.Mandatory }, // LOCAL
                { "S-1-2-1", groupAttributes | SE_GROUP_ATTRIBUTES.Mandatory }, // CONSOLE LOGON
                { "S-1-5-6", groupAttributes | SE_GROUP_ATTRIBUTES.Mandatory }, // NT AUTHORITY\SERVICE
                { "S-1-5-11", groupAttributes | SE_GROUP_ATTRIBUTES.Mandatory }, // NT AUTHORITY\Authenticated Users
                { "S-1-5-18", groupAttributes | SE_GROUP_ATTRIBUTES.Mandatory }, // NT AUTHORITY\SYSTEM
                { "S-1-5-32-544", groupAttributes | SE_GROUP_ATTRIBUTES.Owner }, // BUILTIN\Administrators
                { "S-1-5-32-545", groupAttributes | SE_GROUP_ATTRIBUTES.Mandatory }, // BUILTIN\Users
                { "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", groupAttributes | SE_GROUP_ATTRIBUTES.Owner }, // NT SERVICE\TrustedInstaller
                { "S-1-16-16384", SE_GROUP_ATTRIBUTES.Integrity | SE_GROUP_ATTRIBUTES.IntegrityEnabled } // Mandatory Label\System Mandatory Level
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
                tokenGroups.Add(logonSessionSid, groupAttributes | SE_GROUP_ATTRIBUTES.LogonId);

            foreach (var sid in extraGroupSids)
            {
                if (Regex.IsMatch(sid, @"^S(-\d+){2,}$", RegexOptions.IgnoreCase))
                    tokenGroups.Add(sid.ToUpper(), groupAttributes);
            }

            foreach (var strSid in extraGroupSids)
            {
                SID_NAME_USE sidType = Helpers.GetSidType(strSid);

                if (!tokenGroups.ContainsKey(strSid) &&
                    ((sidType == SID_NAME_USE.WellKnownGroup) || (sidType == SID_NAME_USE.Alias) || (sidType == SID_NAME_USE.Group)))
                {
                    tokenGroups.Add(
                        strSid,
                        SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault | SE_GROUP_ATTRIBUTES.Mandatory);
                }
            }

            pTokenGroups = Marshal.AllocHGlobal(nGroupOffset + (nGroupSize * tokenGroups.Count));
            nOffset = nGroupOffset;

            foreach (var group in tokenGroups)
            {
                groupSids.Add(group.Key, Helpers.ConvertStringSidToSid(group.Key, out int _));
                Marshal.WriteIntPtr(pTokenGroups, nOffset, groupSids[group.Key]);
                Marshal.WriteInt32(pTokenGroups, nOffset + IntPtr.Size, (int)group.Value);
                nOffset += nGroupSize;
            }

            Marshal.WriteInt32(pTokenGroups, tokenGroups.Count);
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


        public static bool GetS4uLogonAccount(
            out string upn,
            out string domain,
            out LSA_STRING pkgName,
            out TOKEN_SOURCE tokenSource)
        {
            int nDosErrorCode = 0;
            var bSuccess = false;
            var fqdn = Helpers.GetCurrentDomainName();
            upn = null;
            domain = null;
            pkgName = new LSA_STRING();
            tokenSource = new TOKEN_SOURCE();

            if (string.Compare(fqdn, Environment.MachineName, true) != 0)
            {
                var accountName = string.Format(@"{0}\{1}", domain, upn);
                bSuccess = Helpers.ConvertAccountNameToSid(
                    ref accountName,
                    out string strSid,
                    out SID_NAME_USE _);

                if (bSuccess)
                {
                    if (Regex.IsMatch(strSid, @"^S-1-5-21(-\d+)+$", RegexOptions.IgnoreCase))
                    {
                        upn = Environment.UserName;
                        domain = fqdn;
                        pkgName = new LSA_STRING(Win32Consts.NEGOSSP_NAME);
                        tokenSource = new TOKEN_SOURCE("NtLmSsp");
                    }
                    else
                    {
                        bSuccess = false;
                    }
                }
            }

            if (!bSuccess)
            {
                bSuccess = Helpers.GetLocalAccounts(out Dictionary<string, bool> localAccounts);

                if (bSuccess)
                {
                    foreach (var account in localAccounts)
                    {
                        if (account.Value)
                        {
                            upn = account.Key;
                            domain = Environment.MachineName;
                            pkgName = new LSA_STRING(Win32Consts.MSV1_0_PACKAGE_NAME);
                            tokenSource = new TOKEN_SOURCE("User32");
                            break;
                        }
                    }

                    if (string.IsNullOrEmpty(upn))
                    {
                        nDosErrorCode = 0x490; // ERROR_NOT_FOUND
                        bSuccess = false;
                    }
                }
                else
                {
                    nDosErrorCode = Marshal.GetLastWin32Error();
                }
            }

            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return bSuccess;
        }


        public static IntPtr GetTrustedInstallerTokenWithS4uLogon(
            string upn,
            string domain,
            in LSA_STRING pkgName,
            in TOKEN_SOURCE tokenSource,
            in List<string> extraGroupSids)
        {
            int nDosErrorCode;
            NTSTATUS ntstatus;
            var hS4ULogonToken = IntPtr.Zero;
            var logonProcessName = new LSA_STRING("User32LogonProcess");
            var tokenGroups = new Dictionary<string, SE_GROUP_ATTRIBUTES>
            {
                {
                    // BUILTIN\Administrators
                    "S-1-5-32-544",
                    SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault | SE_GROUP_ATTRIBUTES.Owner
                },
                {
                    // NT AUTHORITY\LOCAL SERVICE
                    "S-1-5-19",
                    SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault | SE_GROUP_ATTRIBUTES.Mandatory
                },
                {
                    // NT SERVICE\TrustedInstaller
                    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
                    SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault | SE_GROUP_ATTRIBUTES.Owner
                }
            };
            string sessionSid = Helpers.GetCurrentLogonSessionSid();

            if (string.IsNullOrEmpty(sessionSid))
                sessionSid = Helpers.GetExplorerLogonSessionSid();

            if (string.IsNullOrEmpty(sessionSid))
                return IntPtr.Zero;

            foreach (var strSid in extraGroupSids)
            {
                SID_NAME_USE sidType = Helpers.GetSidType(strSid);

                if (!tokenGroups.ContainsKey(strSid) &&
                    ((sidType == SID_NAME_USE.WellKnownGroup) || (sidType == SID_NAME_USE.Alias) || (sidType == SID_NAME_USE.Group)))
                {
                    tokenGroups.Add(
                        strSid,
                        SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault | SE_GROUP_ATTRIBUTES.Mandatory);
                }
            }

            ntstatus = NativeMethods.LsaRegisterLogonProcess(in logonProcessName, out IntPtr hLsa, out uint _);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                nDosErrorCode = NativeMethods.LsaNtStatusToWinError(ntstatus);
                NativeMethods.RtlSetLastWin32Error(nDosErrorCode);
                return IntPtr.Zero;
            }

            do
            {
                ntstatus = NativeMethods.LsaLookupAuthenticationPackage(hLsa, in pkgName, out uint nAuthPkg);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                using (var msv = new MSV1_0_S4U_LOGON(MSV1_0_LOGON_SUBMIT_TYPE.S4ULogon, 0, upn, domain))
                {
                    var originName = new LSA_STRING("S4U");
                    var nGroupOffset = Marshal.OffsetOf(typeof(TOKEN_GROUPS), "Groups").ToInt32();
                    var nUnitSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
                    var pSids = new Dictionary<string, IntPtr>();
                    var attributes = SE_GROUP_ATTRIBUTES.Enabled |
                        SE_GROUP_ATTRIBUTES.EnabledByDefault |
                        SE_GROUP_ATTRIBUTES.LogonId |
                        SE_GROUP_ATTRIBUTES.Mandatory;
                    var nGroupCount = 1 + tokenGroups.Count;
                    var nTokenGroupsLength = nGroupOffset + (nUnitSize * nGroupCount);
                    var pTokenGroups = Marshal.AllocHGlobal(nTokenGroupsLength);
                    var nEntryOffset = nGroupOffset;
                    var phToken = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteInt32(pTokenGroups, nGroupCount);

                    if (!string.IsNullOrEmpty(sessionSid))
                    {
                        pSids.Add(sessionSid, Helpers.ConvertStringSidToSid(sessionSid, out int _));
                        Marshal.WriteIntPtr(pTokenGroups, nEntryOffset, pSids[sessionSid]);
                        Marshal.WriteInt32(pTokenGroups, nEntryOffset + IntPtr.Size, (int)attributes);
                        nEntryOffset += nUnitSize;
                    }

                    foreach (var group in tokenGroups)
                    {
                        pSids.Add(group.Key, Helpers.ConvertStringSidToSid(group.Key, out int _));
                        Marshal.WriteIntPtr(pTokenGroups, nEntryOffset, pSids[group.Key]);
                        Marshal.WriteInt32(pTokenGroups, nEntryOffset + IntPtr.Size, (int)group.Value);
                        nEntryOffset += nUnitSize;
                    }

                    ntstatus = NativeMethods.LsaLogonUser(
                        hLsa,
                        in originName,
                        SECURITY_LOGON_TYPE.Network,
                        nAuthPkg,
                        msv.Buffer,
                        (uint)msv.Length,
                        pTokenGroups,
                        in tokenSource,
                        out IntPtr ProfileBuffer,
                        out uint ProfileBufferLength,
                        out LUID LogonId,
                        phToken,
                        out QUOTA_LIMITS Quotas,
                        out NTSTATUS SubStatus);

                    if (ntstatus == Win32Consts.STATUS_SUCCESS)
                        hS4ULogonToken = Marshal.ReadIntPtr(phToken);

                    foreach (var pSid in pSids.Values)
                        Marshal.FreeHGlobal(pSid);

                    Marshal.FreeHGlobal(pTokenGroups);
                    Marshal.FreeHGlobal(phToken);
                }
            } while (false);

            nDosErrorCode = NativeMethods.LsaNtStatusToWinError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);
            NativeMethods.LsaDeregisterLogonProcess(hLsa);

            return hS4ULogonToken;
        }


        public static IntPtr GetTrustedInstallerTokenWithServiceLogon(
            string username,
            string domain,
            in List<string> extraGroupSids)
        {
            // When set pTokenGroups of LogonUserExExW, it must contain entry for logon SID,
            // otherwise LogonUserExExW will be failed with ERROR_NOT_ENOUGH_MEMORY or some error.
            bool bSuccess;
            int nDosErrorCode = 0;
            var hToken = IntPtr.Zero;
            var tokenGroups = new Dictionary<string, SE_GROUP_ATTRIBUTES>
            {
                {
                    // BUILTIN\Administrators
                    "S-1-5-32-544",
                    SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault | SE_GROUP_ATTRIBUTES.Owner
                },
                {
                    // NT AUTHORITY\LOCAL SERVICE
                    "S-1-5-19",
                    SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault | SE_GROUP_ATTRIBUTES.Mandatory
                },
                {
                    // NT SERVICE\TrustedInstaller
                    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
                    SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault | SE_GROUP_ATTRIBUTES.Owner
                }
            };
            string sessionSid = Helpers.GetCurrentLogonSessionSid();

            // If failed to get current process logon session SID, try to get logon session SID
            // from explorer.exe process.
            if (string.IsNullOrEmpty(sessionSid))
                sessionSid = Helpers.GetExplorerLogonSessionSid();

            foreach (var strSid in extraGroupSids)
            {
                SID_NAME_USE sidType = Helpers.GetSidType(strSid);

                if (!tokenGroups.ContainsKey(strSid) &&
                    ((sidType == SID_NAME_USE.WellKnownGroup) || (sidType == SID_NAME_USE.Alias) || (sidType == SID_NAME_USE.Group)))
                {
                    tokenGroups.Add(
                        strSid,
                        SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault | SE_GROUP_ATTRIBUTES.Mandatory);
                }
            }

            if (!string.IsNullOrEmpty(sessionSid))
            {
                var nGroupOffset = Marshal.OffsetOf(typeof(TOKEN_GROUPS), "Groups").ToInt32();
                var nUnitSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
                var pSids = new Dictionary<string, IntPtr>();
                var attributes = SE_GROUP_ATTRIBUTES.Enabled |
                    SE_GROUP_ATTRIBUTES.EnabledByDefault |
                    SE_GROUP_ATTRIBUTES.LogonId |
                    SE_GROUP_ATTRIBUTES.Mandatory;
                var nGroupCount = 1 + tokenGroups.Count;
                var nTokenGroupsLength = nGroupOffset + (nUnitSize * nGroupCount);
                var pTokenGroups = Marshal.AllocHGlobal(nTokenGroupsLength);
                var nEntryOffset = nGroupOffset;
                Marshal.WriteInt32(pTokenGroups, nGroupCount);
                pSids.Add(sessionSid, Helpers.ConvertStringSidToSid(sessionSid, out int _));

                // In TOKEN_GROUPS buffer, logon session SID entry must be placed before extra 
                // group SIDs, otherwise LogonUserExExW will be failed with ERROR_ACCESS_DENIED.
                Marshal.WriteIntPtr(pTokenGroups, nEntryOffset, pSids[sessionSid]);
                Marshal.WriteInt32(pTokenGroups, nEntryOffset + IntPtr.Size, (int)attributes);
                nEntryOffset += nUnitSize;

                foreach (var group in tokenGroups)
                {
                    pSids.Add(group.Key, Helpers.ConvertStringSidToSid(group.Key, out int _));
                    Marshal.WriteIntPtr(pTokenGroups, nEntryOffset, pSids[group.Key]);
                    Marshal.WriteInt32(pTokenGroups, nEntryOffset + IntPtr.Size, (int)group.Value);
                    nEntryOffset += nUnitSize;
                }

                bSuccess = NativeMethods.LogonUserExExW(
                    username,
                    domain,
                    null,
                    LOGON_TYPE.Service,
                    LOGON_PROVIDER.Default,
                    pTokenGroups,
                    out hToken,
                    out IntPtr _,
                    out IntPtr _,
                    out int _,
                    out QUOTA_LIMITS _);

                if (!bSuccess)
                {
                    hToken = IntPtr.Zero;
                    nDosErrorCode = Marshal.GetLastWin32Error();
                }

                Marshal.FreeHGlobal(pTokenGroups);

                foreach (var pSid in pSids.Values)
                    Marshal.FreeHGlobal(pSid);
            }
            else
            {
                nDosErrorCode = Marshal.GetLastWin32Error();
            }

            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return hToken;
        }


        public static IntPtr GetTrustedInstallerTokenWithVirtualLogon(
            string username,
            string domain,
            in List<string> extraGroupSids)
        {
            // When set pTokenGroups of LogonUserExExW, it must contain entry for logon SID,
            // otherwise LogonUserExExW will be failed with ERROR_NOT_ENOUGH_MEMORY or some error.
            bool bSuccess;
            int nDosErrorCode = 0;
            var hToken = IntPtr.Zero;
            var tokenGroups = new Dictionary<string, SE_GROUP_ATTRIBUTES>
            {
                {
                    // BUILTIN\Administrators
                    "S-1-5-32-544",
                    SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault | SE_GROUP_ATTRIBUTES.Owner
                },
                {
                    // NT AUTHORITY\LOCAL SERVICE
                    "S-1-5-19",
                    SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault | SE_GROUP_ATTRIBUTES.Mandatory
                },
                {
                    // NT SERVICE\TrustedInstaller
                    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
                    SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault | SE_GROUP_ATTRIBUTES.Owner
                }
            };
            string sessionSid = Helpers.GetCurrentLogonSessionSid();

            // If failed to get current process logon session SID, try to get logon session SID
            // from explorer.exe process.
            if (string.IsNullOrEmpty(sessionSid))
                sessionSid = Helpers.GetExplorerLogonSessionSid();

            foreach (var strSid in extraGroupSids)
            {
                SID_NAME_USE sidType = Helpers.GetSidType(strSid);

                if (!tokenGroups.ContainsKey(strSid) &&
                    ((sidType == SID_NAME_USE.WellKnownGroup) || (sidType == SID_NAME_USE.Alias) || (sidType == SID_NAME_USE.Group)))
                {
                    tokenGroups.Add(
                        strSid,
                        SE_GROUP_ATTRIBUTES.Enabled | SE_GROUP_ATTRIBUTES.EnabledByDefault | SE_GROUP_ATTRIBUTES.Mandatory);
                }
            }

            if (!string.IsNullOrEmpty(sessionSid))
            {
                var nGroupOffset = Marshal.OffsetOf(typeof(TOKEN_GROUPS), "Groups").ToInt32();
                var nUnitSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
                var pSids = new Dictionary<string, IntPtr>();
                var attributes = SE_GROUP_ATTRIBUTES.Enabled |
                    SE_GROUP_ATTRIBUTES.EnabledByDefault |
                    SE_GROUP_ATTRIBUTES.LogonId |
                    SE_GROUP_ATTRIBUTES.Mandatory;
                var nGroupCount = 1 + tokenGroups.Count;
                var nTokenGroupsLength = nGroupOffset + (nUnitSize * nGroupCount);
                var pTokenGroups = Marshal.AllocHGlobal(nTokenGroupsLength);
                var nEntryOffset = nGroupOffset;
                Marshal.WriteInt32(pTokenGroups, nGroupCount);
                pSids.Add(sessionSid, Helpers.ConvertStringSidToSid(sessionSid, out int _));

                // In TOKEN_GROUPS buffer, logon session SID entry must be placed before extra 
                // group SIDs, otherwise LogonUserExExW will be failed with ERROR_ACCESS_DENIED.
                Marshal.WriteIntPtr(pTokenGroups, nEntryOffset, pSids[sessionSid]);
                Marshal.WriteInt32(pTokenGroups, nEntryOffset + IntPtr.Size, (int)attributes);
                nEntryOffset += nUnitSize;

                foreach (var group in tokenGroups)
                {
                    pSids.Add(group.Key, Helpers.ConvertStringSidToSid(group.Key, out int _));
                    Marshal.WriteIntPtr(pTokenGroups, nEntryOffset, pSids[group.Key]);
                    Marshal.WriteInt32(pTokenGroups, nEntryOffset + IntPtr.Size, (int)group.Value);
                    nEntryOffset += nUnitSize;
                }

                bSuccess = NativeMethods.LogonUserExExW(
                    username,
                    domain,
                    null,
                    LOGON_TYPE.Interactive,
                    LOGON_PROVIDER.Virtual,
                    pTokenGroups,
                    out hToken,
                    out IntPtr _,
                    out IntPtr _,
                    out int _,
                    out QUOTA_LIMITS _);

                if (!bSuccess)
                {
                    hToken = IntPtr.Zero;
                    nDosErrorCode = Marshal.GetLastWin32Error();
                }

                Marshal.FreeHGlobal(pTokenGroups);

                foreach (var pSid in pSids.Values)
                    Marshal.FreeHGlobal(pSid);
            }
            else
            {
                nDosErrorCode = Marshal.GetLastWin32Error();
            }

            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return hToken;
        }


        public static bool ImpersonateAsSmss(
            in List<SE_PRIVILEGE_ID> requiredPrivs,
            out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs)
        {
            bool bSuccess;
            int nSmssId;
            IntPtr hImpersonationToken;

            try
            {
                nSmssId = Process.GetProcessesByName("smss")[0].Id;
            }
            catch
            {
                adjustedPrivs = new Dictionary<SE_PRIVILEGE_ID, bool>();
                NativeMethods.RtlSetLastWin32Error(5); // ERROR_ACCESS_DENIED
                return false;
            }

            hImpersonationToken = Helpers.GetProcessToken(nSmssId, TOKEN_TYPE.Impersonation);

            if (hImpersonationToken == IntPtr.Zero)
            {
                adjustedPrivs = new Dictionary<SE_PRIVILEGE_ID, bool>();
                NativeMethods.RtlSetLastWin32Error(5);

                foreach (var priv in requiredPrivs)
                    adjustedPrivs.Add(priv, false);

                return false;
            }

            Helpers.EnableTokenPrivileges(
                hImpersonationToken,
                in requiredPrivs,
                out adjustedPrivs);
            bSuccess = Helpers.ImpersonateThreadToken(new IntPtr(-2), hImpersonationToken);
            NativeMethods.NtClose(hImpersonationToken);

            return bSuccess;
        }
    }
}
