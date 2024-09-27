using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using S4ULogonShell.Interop;

namespace S4ULogonShell.Library
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


        public static IntPtr GetS4uLogonToken(
            string upn,
            string domain,
            in LSA_STRING pkgName,
            in TOKEN_SOURCE tokenSource,
            in Dictionary<string, SE_GROUP_ATTRIBUTES> extraTokenGroups)
        {
            int nDosErrorCode;
            NTSTATUS ntstatus;
            var hS4ULogonToken = IntPtr.Zero;
            var logonProcessName = new LSA_STRING("User32LogonProcess");
            string sessionSid = Helpers.GetCurrentLogonSessionSid();

            if (string.IsNullOrEmpty(sessionSid))
                sessionSid = Helpers.GetExplorerLogonSessionSid();

            if (string.IsNullOrEmpty(sessionSid))
                return IntPtr.Zero;

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
                    var nGroupCount = 1 + extraTokenGroups.Count;
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

                    foreach (var group in extraTokenGroups)
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


        public static bool ImpersonateAsWinlogon(
            in List<SE_PRIVILEGE_ID> requiredPrivs,
            out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs)
        {
            bool bSuccess;
            IntPtr hImpersonationToken;

            hImpersonationToken = Helpers.GetWinlogonToken(TOKEN_TYPE.Impersonation);

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
