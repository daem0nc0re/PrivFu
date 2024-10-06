using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using ServiceShell.Interop;

namespace ServiceShell.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static string ConvertSidToStringSid(IntPtr pSid)
        {
            var stringSidBuilder = new StringBuilder("S");
            int nAuthorityCount = Marshal.ReadByte(pSid, 1);
            long nAuthority = 0;
            stringSidBuilder.AppendFormat("-{0}", Marshal.ReadByte(pSid));

            for (var idx = 2; idx < 8; idx++)
                nAuthority = (nAuthority << 8) | Marshal.ReadByte(pSid, idx);

            stringSidBuilder.AppendFormat("-{0}", nAuthority);

            for (var idx = 0; idx < nAuthorityCount; idx++)
                stringSidBuilder.AppendFormat("-{0}", (uint)Marshal.ReadInt32(pSid, 8 + (idx * 4)));

            return stringSidBuilder.ToString();
        }


        public static IntPtr ConvertStringSidToSid(string stringSid, out int nInfoLength)
        {
            var pInfoBuffer = IntPtr.Zero;
            nInfoLength = 0;

            try
            {
                if (Regex.IsMatch(stringSid, @"^S(-\d+){2,}$", RegexOptions.IgnoreCase))
                {
                    string[] stringSidArray = stringSid.Split('-');
                    byte nRevision = (byte)(Convert.ToInt64(stringSidArray[1], 10) & 0xFF);
                    byte nSubAuthorityCount = (byte)((stringSidArray.Length - 3) & 0xFF);
                    long nAuthority = Convert.ToInt64(stringSidArray[2], 10) & 0x0000FFFFFFFFFFFF;
                    nInfoLength = 8 + (nSubAuthorityCount * 4);
                    pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
                    Marshal.WriteByte(pInfoBuffer, nRevision);
                    Marshal.WriteByte(pInfoBuffer, 1, nSubAuthorityCount);

                    for (var idx = 0; idx < 6; idx++)
                        Marshal.WriteByte(pInfoBuffer, 7 - idx, (byte)((nAuthority >> (idx * 8)) & 0xFF));

                    for (var idx = 0; idx < nSubAuthorityCount; idx++)
                        Marshal.WriteInt32(pInfoBuffer, 8 + (idx * 4), (int)(Convert.ToUInt32(stringSidArray[3 + idx], 10)));
                }
            }
            catch
            {
                if (pInfoBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pInfoBuffer);
                    pInfoBuffer = IntPtr.Zero;
                    nInfoLength = 0;
                }
            }

            return pInfoBuffer;
        }


        public static bool EnableAllTokenPrivileges(
            IntPtr hToken,
            out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs)
        {
            bool bAllEnabled;
            int nDosErrorCode;
            IntPtr pInfoBuffer;
            NTSTATUS nErrorStatus = Win32Consts.STATUS_SUCCESS;
            adjustedPrivs = new Dictionary<SE_PRIVILEGE_ID, bool>();
            bAllEnabled = GetTokenPrivileges(
                hToken,
                out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

            if (!bAllEnabled)
                return false;

            pInfoBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));

            foreach (var priv in availablePrivs)
            {
                NTSTATUS ntstatus;
                var info = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new LUID_AND_ATTRIBUTES[1]
                };
                adjustedPrivs.Add(priv.Key, false);

                if ((priv.Value & SE_PRIVILEGE_ATTRIBUTES.Enabled) != 0)
                {
                    adjustedPrivs[priv.Key] = true;
                    continue;
                }

                info.Privileges[0].Luid.QuadPart = (long)priv.Key;
                info.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.Enabled;
                Marshal.StructureToPtr(info, pInfoBuffer, true);
                ntstatus = NativeMethods.NtAdjustPrivilegesToken(
                    hToken,
                    BOOLEAN.FALSE,
                    pInfoBuffer,
                    (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)),
                    IntPtr.Zero,
                    out uint _);
                adjustedPrivs[priv.Key] = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    nErrorStatus = ntstatus;
                    bAllEnabled = false;
                }
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(nErrorStatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);
            Marshal.FreeHGlobal(pInfoBuffer);

            return bAllEnabled;
        }


        public static bool EnableTokenPrivileges(
            in List<SE_PRIVILEGE_ID> requiredPrivs,
            out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs)
        {
            return EnableTokenPrivileges(
                WindowsIdentity.GetCurrent().Token,
                in requiredPrivs,
                out adjustedPrivs);
        }


        public static bool EnableTokenPrivileges(
            IntPtr hToken,
            in List<SE_PRIVILEGE_ID> privsToEnable,
            out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs)
        {
            bool bAllEnabled;
            int nDosErrorCode;
            IntPtr pInfoBuffer;
            NTSTATUS nErrorStatus = Win32Consts.STATUS_SUCCESS;
            adjustedPrivs = new Dictionary<SE_PRIVILEGE_ID, bool>();

            foreach (var id in privsToEnable)
                adjustedPrivs.Add(id, false);

            if (privsToEnable.Count == 0)
                return true;

            bAllEnabled = GetTokenPrivileges(
                hToken,
                out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

            if (!bAllEnabled)
                return false;

            pInfoBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));

            foreach (var priv in privsToEnable)
            {
                NTSTATUS ntstatus;
                var info = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new LUID_AND_ATTRIBUTES[1]
                };

                if (!availablePrivs.ContainsKey(priv))
                {
                    nErrorStatus = Win32Consts.STATUS_PRIVILEGE_NOT_HELD;
                    bAllEnabled = false;
                    continue;
                }

                if ((availablePrivs[priv] & SE_PRIVILEGE_ATTRIBUTES.Enabled) != 0)
                {
                    adjustedPrivs[priv] = true;
                    continue;
                }

                info.Privileges[0].Luid.QuadPart = (long)priv;
                info.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.Enabled;
                Marshal.StructureToPtr(info, pInfoBuffer, true);
                ntstatus = NativeMethods.NtAdjustPrivilegesToken(
                    hToken,
                    BOOLEAN.FALSE,
                    pInfoBuffer,
                    (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)),
                    IntPtr.Zero,
                    out uint _);
                adjustedPrivs[priv] = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    nErrorStatus = ntstatus;
                    bAllEnabled = false;
                }
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(nErrorStatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);
            Marshal.FreeHGlobal(pInfoBuffer);

            return bAllEnabled;
        }


        public static string GetCurrentLogonSessionSid()
        {
            int nDosErrorCode;
            string stringSid = null;
            NTSTATUS ntstatus = NativeMethods.NtOpenProcessToken(
                new IntPtr(-1),
                ACCESS_MASK.TOKEN_QUERY,
                out IntPtr hToken);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                GetTokenGroups(hToken, out Dictionary<string, SE_GROUP_ATTRIBUTES> tokenGroups);
                nDosErrorCode = Marshal.GetLastWin32Error();
                NativeMethods.NtClose(hToken);

                foreach (var group in tokenGroups)
                {
                    if ((group.Value & SE_GROUP_ATTRIBUTES.LogonId) != 0)
                    {
                        stringSid = group.Key;
                        break;
                    }
                }
            }
            else
            {
                nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            }

            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return stringSid;
        }


        public static string GetExplorerLogonSessionSid()
        {
            NTSTATUS ntstatus;
            int nDosErrorCode = 0;
            string stringSid = null;
            var objectAttributes = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
            };
            var clientId = new CLIENT_ID();

            try
            {
                var nExplorerPid = Process.GetProcessesByName("explorer")[0].Id;
                clientId.UniqueProcess = new IntPtr(nExplorerPid);
            }
            catch
            {
                NativeMethods.RtlSetLastWin32Error(0x490); // ERROR_NOT_FOUND
                return null;
            }

            do
            {
                ntstatus = NativeMethods.NtOpenProcess(
                    out IntPtr hProcess,
                    ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                    in objectAttributes,
                    in clientId);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                ntstatus = NativeMethods.NtOpenProcessToken(
                    hProcess,
                    ACCESS_MASK.TOKEN_QUERY,
                    out IntPtr hToken);
                NativeMethods.NtClose(hProcess);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                GetTokenGroups(hToken, out Dictionary<string, SE_GROUP_ATTRIBUTES> tokenGroups);
                nDosErrorCode = Marshal.GetLastWin32Error();
                NativeMethods.NtClose(hToken);

                foreach (var group in tokenGroups)
                {
                    if ((group.Value & SE_GROUP_ATTRIBUTES.LogonId) != 0)
                    {
                        stringSid = group.Key;
                        break;
                    }
                }
            } while (false);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
                nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);

            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return stringSid;
        }


        internal static int GetGuiSessionId()
        {
            int nGuiSessionId = -1;
            bool bSuccess = NativeMethods.WTSEnumerateSessionsW(
                IntPtr.Zero,
                0,
                1,
                out IntPtr pSessionInfo,
                out int nCount);

            if (!bSuccess)
                return -1;

            for (var idx = 0; idx < nCount; idx++)
            {
                IntPtr pInfoBuffer;
                int nOffset = Marshal.SizeOf(typeof(WTS_SESSION_INFOW)) * idx;

                if (Environment.Is64BitProcess)
                    pInfoBuffer = new IntPtr(pSessionInfo.ToInt64() + nOffset);
                else
                    pInfoBuffer = new IntPtr(pSessionInfo.ToInt32() + nOffset);

                var info = (WTS_SESSION_INFOW)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(WTS_SESSION_INFOW));

                if (info.State == WTS_CONNECTSTATE_CLASS.Active)
                {
                    nGuiSessionId = info.SessionId;
                    break;
                }
            }

            NativeMethods.WTSFreeMemory(pSessionInfo);

            if (nGuiSessionId == -1)
                NativeMethods.RtlSetLastWin32Error(1168); // ERROR_NOT_FOUND

            return nGuiSessionId;
        }


        public static IntPtr GetProcessToken(int pid, TOKEN_TYPE tokenType)
        {
            NTSTATUS ntstatus;
            var hDupToken = IntPtr.Zero;
            var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(pid) };
            var objectAttributes = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
            };
            var nContextSize = Marshal.SizeOf(typeof(SECURITY_QUALITY_OF_SERVICE));
            var context = new SECURITY_QUALITY_OF_SERVICE
            {
                Length = nContextSize,
                ImpersonationLevel = SECURITY_IMPERSONATION_LEVEL.Impersonation
            };
            var pContextBuffer = Marshal.AllocHGlobal(nContextSize);
            Marshal.StructureToPtr(context, pContextBuffer, true);

            if (tokenType == TOKEN_TYPE.Impersonation)
                objectAttributes.SecurityQualityOfService = pContextBuffer;

            do
            {
                ntstatus = NativeMethods.NtOpenProcess(
                    out IntPtr hProcess,
                    ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                    in objectAttributes,
                    in clientId);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                ntstatus = NativeMethods.NtOpenProcessToken(
                    hProcess,
                    ACCESS_MASK.TOKEN_DUPLICATE,
                    out IntPtr hToken);
                NativeMethods.NtClose(hProcess);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                ntstatus = NativeMethods.NtDuplicateToken(
                    hToken,
                    ACCESS_MASK.MAXIMUM_ALLOWED,
                    in objectAttributes,
                    BOOLEAN.FALSE,
                    tokenType,
                    out hDupToken);
                NativeMethods.NtClose(hToken);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    hDupToken = IntPtr.Zero;
            } while (false);

            ntstatus = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(ntstatus);
            Marshal.FreeHGlobal(pContextBuffer);

            return hDupToken;
        }


        public static bool GetTokenGroups(
            IntPtr hToken,
            out Dictionary<string, SE_GROUP_ATTRIBUTES> tokenGroups)
        {
            int nDosErrorCode;
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_GROUPS));
            tokenGroups = new Dictionary<string, SE_GROUP_ATTRIBUTES>();

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenGroups,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var nGroupCount = Marshal.ReadInt32(pInfoBuffer);
                var nGroupOffset = Marshal.OffsetOf(typeof(TOKEN_GROUPS), "Groups").ToInt32();
                var nUnitSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));

                for (var idx = 0; idx < nGroupCount; idx++)
                {
                    var nEntryOffset = nGroupOffset + (idx * nUnitSize);
                    var pSid = Marshal.ReadIntPtr(pInfoBuffer, nEntryOffset);
                    var nAttribute = Marshal.ReadInt32(pInfoBuffer, nEntryOffset + IntPtr.Size);
                    tokenGroups.Add(ConvertSidToStringSid(pSid), (SE_GROUP_ATTRIBUTES)nAttribute);
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetTokenPrivileges(
            IntPtr hToken,
            out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> privileges)
        {
            int nDosErrorCode;
            var nOffset = Marshal.OffsetOf(typeof(TOKEN_PRIVILEGES), "Privileges").ToInt32();
            var nUnitSize = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
            var nInfoLength = (uint)(nOffset + (nUnitSize * 36));
            var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenPrivileges,
                pInfoBuffer,
                nInfoLength,
                out uint _);
            privileges = new Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES>();

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                int nPrivilegeCount = Marshal.ReadInt32(pInfoBuffer);

                for (var idx = 0; idx < nPrivilegeCount; idx++)
                {
                    privileges.Add(
                        (SE_PRIVILEGE_ID)Marshal.ReadInt32(pInfoBuffer, nOffset),
                        (SE_PRIVILEGE_ATTRIBUTES)Marshal.ReadInt32(pInfoBuffer, nOffset + 8));
                    nOffset += nUnitSize;
                }
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);
            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static IntPtr GetWinlogonToken(TOKEN_TYPE tokenType)
        {
            int nWinlogonId;

            try
            {
                nWinlogonId = Process.GetProcessesByName("winlogon")[0].Id;
            }
            catch
            {
                NativeMethods.RtlSetLastWin32Error(5); // ERROR_ACCESS_DENIED
                return IntPtr.Zero;
            }

            return GetProcessToken(nWinlogonId, tokenType);
        }


        public static bool ImpersonateThreadToken(IntPtr hThread, IntPtr hToken)
        {
            NTSTATUS ntstatus;
            int nDosErrorCode;
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            var bSuccess = false;
            Marshal.WriteIntPtr(pInfoBuffer, IntPtr.Zero);

            do
            {
                SECURITY_IMPERSONATION_LEVEL originalLevel;
                SECURITY_IMPERSONATION_LEVEL grantedLevel;
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenImpersonationLevel,
                    pInfoBuffer,
                    4u,
                    out uint _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;
                else
                    originalLevel = (SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(pInfoBuffer);

                Marshal.WriteIntPtr(pInfoBuffer, hToken);
                ntstatus = NativeMethods.NtSetInformationThread(
                    hThread,
                    THREADINFOCLASS.ThreadImpersonationToken,
                    pInfoBuffer,
                    (uint)IntPtr.Size);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                NativeMethods.NtQueryInformationToken(
                    WindowsIdentity.GetCurrent().Token,
                    TOKEN_INFORMATION_CLASS.TokenImpersonationLevel,
                    pInfoBuffer,
                    4u,
                    out uint _);
                grantedLevel = (SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(pInfoBuffer);
                bSuccess = (grantedLevel == originalLevel);

                if (bSuccess)
                    ntstatus = Win32Consts.STATUS_PRIVILEGE_NOT_HELD;
            } while (false);

            Marshal.FreeHGlobal(pInfoBuffer);
            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError((int)ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return bSuccess;
        }


        public static bool RevertThreadToken(IntPtr hThread)
        {
            int nDosErrorCode;
            NTSTATUS ntstatus;
            var pInfoBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pInfoBuffer, IntPtr.Zero);
            ntstatus = NativeMethods.NtSetInformationThread(
                hThread,
                THREADINFOCLASS.ThreadImpersonationToken,
                pInfoBuffer,
                (uint)IntPtr.Size);
            Marshal.FreeHGlobal(pInfoBuffer);
            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool SetTokenSessionId(IntPtr hToken, int nSessionId)
        {
            int nDosErrorCode;
            NTSTATUS ntstatus;
            var pInfoBuffer = Marshal.AllocHGlobal(4);
            Marshal.WriteInt32(pInfoBuffer, nSessionId);
            ntstatus = NativeMethods.NtSetInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenSessionId,
                pInfoBuffer,
                4u);
            Marshal.FreeHGlobal(pInfoBuffer);
            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }
    }
}
