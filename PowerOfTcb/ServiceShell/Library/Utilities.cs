using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using ServiceShell.Interop;

namespace ServiceShell.Library
{
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


        public static IntPtr GetServiceLogonToken(
            string username,
            string domain,
            in Dictionary<string, SE_GROUP_ATTRIBUTES> extraTokenGroups)
        {
            // When set pTokenGroups of LogonUserExExW, it must contain entry for logon SID,
            // otherwise LogonUserExExW will be failed with ERROR_NOT_ENOUGH_MEMORY or some error.
            bool bSuccess;
            int nDosErrorCode = 0;
            var hToken = IntPtr.Zero;
            string sessionSid = Helpers.GetCurrentLogonSessionSid();

            // If failed to get current process logon session SID, try to get logon session SID
            // from explorer.exe process.
            if (string.IsNullOrEmpty(sessionSid))
                sessionSid = Helpers.GetExplorerLogonSessionSid();

            if (!string.IsNullOrEmpty(sessionSid))
            {
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
                Marshal.WriteInt32(pTokenGroups, nGroupCount);
                pSids.Add(sessionSid, Helpers.ConvertStringSidToSid(sessionSid, out int _));

                // In TOKEN_GROUPS buffer, logon session SID entry must be placed before extra 
                // group SIDs, otherwise LogonUserExExW will be failed with ERROR_ACCESS_DENIED.
                Marshal.WriteIntPtr(pTokenGroups, nEntryOffset, pSids[sessionSid]);
                Marshal.WriteInt32(pTokenGroups, nEntryOffset + IntPtr.Size, (int)attributes);
                nEntryOffset += nUnitSize;

                foreach (var group in extraTokenGroups)
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
