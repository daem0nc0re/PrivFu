using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using S4uDelegator.Interop;

namespace S4uDelegator.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static bool EnableTokenPrivileges(
            List<string> requiredPrivs,
            out Dictionary<string, bool> adjustedPrivs)
        {
            return EnableTokenPrivileges(
                WindowsIdentity.GetCurrent().Token,
                requiredPrivs,
                out adjustedPrivs);
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


        public static IntPtr GetS4uLogonToken(
            string upn,
            string domain,
            in LSA_STRING pkgName,
            in TOKEN_SOURCE tokenSource,
            List<string> groupSids)
        {
            var hS4uLogonToken = IntPtr.Zero;

            do
            {
                IntPtr pTokenGroups;
                int nGroupCount = groupSids.Count;
                var nGroupsOffset = Marshal.OffsetOf(typeof(TOKEN_GROUPS), "Groups").ToInt32();
                var nTokenGroupsSize = nGroupsOffset;
                var pSidBuffersToLocalFree = new List<IntPtr>();
                nTokenGroupsSize += (Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES)) * nGroupCount);

                NTSTATUS ntstatus = NativeMethods.LsaConnectUntrusted(out IntPtr hLsa);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    NativeMethods.SetLastError(NativeMethods.LsaNtStatusToWinError(ntstatus));
                    break;
                }

                ntstatus = NativeMethods.LsaLookupAuthenticationPackage(hLsa, in pkgName, out uint authnPkg);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    NativeMethods.LsaClose(hLsa);
                    NativeMethods.SetLastError(NativeMethods.LsaNtStatusToWinError(ntstatus));
                    break;
                }

                if (nGroupCount > 0)
                {
                    int nUnitSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
                    var attributes = (int)(SE_GROUP_ATTRIBUTES.MANDATORY | SE_GROUP_ATTRIBUTES.ENABLED);
                    pTokenGroups = Marshal.AllocHGlobal(nTokenGroupsSize);
                    nGroupCount = 0;
                    Helpers.ZeroMemory(pTokenGroups, nTokenGroupsSize);

                    foreach (var stringSid in groupSids)
                    {
                        if (NativeMethods.ConvertStringSidToSid(stringSid, out IntPtr pSid))
                        {
                            Helpers.ConvertSidToAccountName(pSid, out string _, out string _, out SID_NAME_USE sidType);

                            if ((sidType == SID_NAME_USE.Alias) ||
                                (sidType == SID_NAME_USE.Group) ||
                                (sidType == SID_NAME_USE.WellKnownGroup))
                            {
                                Marshal.WriteIntPtr(pTokenGroups, (nGroupsOffset + (nGroupCount * nUnitSize)), pSid);
                                Marshal.WriteInt32(pTokenGroups, (nGroupsOffset + (nGroupCount * nUnitSize) + IntPtr.Size), attributes);
                                pSidBuffersToLocalFree.Add(pSid);
                                nGroupCount++;
                            }
                        }
                    }

                    if (nGroupCount == 0)
                    {
                        Marshal.FreeHGlobal(pTokenGroups);
                        pTokenGroups = IntPtr.Zero;
                    }
                    else
                    {
                        Marshal.WriteInt32(pTokenGroups, nGroupCount);
                    }
                }
                else
                {
                    pTokenGroups = IntPtr.Zero;
                }

                using (var msv = new MSV1_0_S4U_LOGON(MSV1_0_LOGON_SUBMIT_TYPE.MsV1_0S4ULogon, 0, upn, domain))
                {
                    IntPtr pTokenBuffer = Marshal.AllocHGlobal(IntPtr.Size);
                    var originName = new LSA_STRING("S4U");
                    ntstatus = NativeMethods.LsaLogonUser(
                        hLsa,
                        in originName,
                        SECURITY_LOGON_TYPE.Network,
                        authnPkg,
                        msv.Buffer,
                        (uint)msv.Length,
                        pTokenGroups,
                        in tokenSource,
                        out IntPtr ProfileBuffer,
                        out uint _,
                        out LUID _,
                        pTokenBuffer,
                        out QUOTA_LIMITS _,
                        out NTSTATUS _);
                    NativeMethods.LsaFreeReturnBuffer(ProfileBuffer);
                    NativeMethods.LsaClose(hLsa);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                        NativeMethods.SetLastError(NativeMethods.LsaNtStatusToWinError(ntstatus));
                    else
                        hS4uLogonToken = Marshal.ReadIntPtr(pTokenBuffer);

                    Marshal.FreeHGlobal(pTokenBuffer);
                }

                if (pTokenGroups != IntPtr.Zero)
                    Marshal.FreeHGlobal(pTokenGroups);

                foreach (var pSidBuffer in pSidBuffersToLocalFree)
                    NativeMethods.LocalFree(pSidBuffer);
            } while (false);

            return hS4uLogonToken;
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
                    ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                    true,
                    smss);

                if (hProcess == IntPtr.Zero)
                    break;

                status = NativeMethods.OpenProcessToken(
                    hProcess,
                    TokenAccessFlags.TOKEN_DUPLICATE,
                    out IntPtr hToken);
                NativeMethods.NtClose(hProcess);

                if (!status)
                    break;

                status = NativeMethods.DuplicateTokenEx(
                    hToken,
                    TokenAccessFlags.MAXIMUM_ALLOWED,
                    IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.Impersonation,
                    TOKEN_TYPE.TokenImpersonation,
                    out IntPtr hDupToken);
                NativeMethods.NtClose(hToken);

                if (!status)
                    break;

                EnableTokenPrivileges(hDupToken, privs, out Dictionary<string, bool> _);
                status = ImpersonateThreadToken(hDupToken);
                NativeMethods.NtClose(hDupToken);
            } while (false);

            return status;
        }


        public static bool ImpersonateThreadToken(IntPtr hImpersonationToken)
        {
            IntPtr pImpersonationLevel = Marshal.AllocHGlobal(4);
            bool status = NativeMethods.ImpersonateLoggedOnUser(hImpersonationToken);

            if (status)
            {
                NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                    WindowsIdentity.GetCurrent().Token,
                    TOKEN_INFORMATION_CLASS.TokenImpersonationLevel,
                    pImpersonationLevel,
                    4u,
                    out uint _);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (status)
                {
                    var level = Marshal.ReadInt32(pImpersonationLevel);
                    status = (level >= (int)SECURITY_IMPERSONATION_LEVEL.Impersonation);
                }
            }

            Marshal.FreeHGlobal(pImpersonationLevel);

            return status;
        }


        public static bool IsGroupSid(ref string stringSid, out string accountName)
        {
            var validTypes = new List<SID_NAME_USE>
            {
                SID_NAME_USE.Alias,
                SID_NAME_USE.Group,
                SID_NAME_USE.WellKnownGroup
            };
            accountName = Helpers.ConvertStringSidToAccountName(
                ref stringSid,
                out SID_NAME_USE sidType);

            return validTypes.Contains(sidType);
        }


        public static bool VerifyAccountName(
            ref string domain,
            ref string name,
            ref string stringSid,
            out string samAccountName,
            out string upn,
            out SID_NAME_USE sidType)
        {
            var isLocalAccount = false;
            var status = false;
            string currentDomain = Helpers.GetCurrentDomainName();
            bool isDomainEnv = !Helpers.CompareIgnoreCase(currentDomain, Environment.UserDomainName);
            upn = null;
            sidType = SID_NAME_USE.Unknown;

            if (!string.IsNullOrEmpty(domain) && (domain.Trim() == "."))
                domain = Environment.MachineName;

            if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(domain))
                samAccountName = string.Format(@"{0}\{1}", domain, name);
            else if (!string.IsNullOrEmpty(name))
                samAccountName = name;
            else if (!string.IsNullOrEmpty(domain))
                samAccountName = domain;
            else
                samAccountName = null;

            if (!string.IsNullOrEmpty(stringSid))
            {
                if (Regex.IsMatch(stringSid, @"^S(-[0-9]+)+$", RegexOptions.IgnoreCase))
                    stringSid = stringSid.ToUpper();
                else
                    return false;
            }

            do
            {
                if (!string.IsNullOrEmpty(stringSid))
                {
                    samAccountName = Helpers.ConvertStringSidToAccountName(
                        ref stringSid,
                        out sidType);
                    var nameArray = samAccountName.Split('\\');

                    if (nameArray.Length == 2)
                    {
                        domain = nameArray[0];
                        name = nameArray[1];
                    }
                    else
                    {
                        name = nameArray[0];
                    }
                }
                else if (!string.IsNullOrEmpty(samAccountName))
                {
                    stringSid = Helpers.ConvertAccountNameToStringSid(
                        ref samAccountName,
                        out sidType);
                }

                if (string.IsNullOrEmpty(samAccountName) || string.IsNullOrEmpty(stringSid))
                    break;

                if (sidType == SID_NAME_USE.User)
                {
                    Helpers.GetLocalUsers(out Dictionary<string, bool> localUsers);

                    foreach (var username in localUsers.Keys)
                    {
                        var samAccountNameUser = string.Format(
                            @"{0}\{1}",
                            Environment.MachineName,
                            username);
                        string userSid = Helpers.ConvertAccountNameToStringSid(
                            ref samAccountNameUser,
                            out SID_NAME_USE _);

                        if (Helpers.CompareIgnoreCase(userSid, stringSid))
                        {
                            isLocalAccount = true;
                            break;
                        }
                    }
                }
                else if (sidType == SID_NAME_USE.Group)
                {
                    Helpers.GetLocalGroups(out List<string> localGroups);

                    foreach (var groupname in localGroups)
                    {
                        var samAccountNameGroup = string.Format(
                            @"{0}\{1}",
                            Environment.MachineName,
                            groupname);
                        string userSid = Helpers.ConvertAccountNameToStringSid(
                            ref samAccountNameGroup,
                            out SID_NAME_USE _);

                        if (Helpers.CompareIgnoreCase(userSid, stringSid))
                        {
                            isLocalAccount = true;
                            break;
                        }
                    }
                }

                if (((sidType == SID_NAME_USE.User) || (sidType == SID_NAME_USE.Group)) &&
                    isDomainEnv &&
                    !isLocalAccount)
                {
                    string fullDomainName = currentDomain;
                    string domainSid = Helpers.ConvertAccountNameToStringSid(
                        ref currentDomain,
                        out SID_NAME_USE _);

                    if (string.IsNullOrEmpty(domainSid))
                        break;

                    if (Regex.IsMatch(
                        stringSid,
                        string.Format("^{0}", domainSid),
                        RegexOptions.IgnoreCase))
                    {
                        upn = string.Format("{0}@{1}", name, fullDomainName);
                        status = true;
                    }
                }
                else
                {
                    status = true;
                }
            } while (false);

            return status;
        }
    }
}
