using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using TokenAssignor.Interop;

namespace TokenAssignor.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static bool AssignProcessToken(
            IntPtr hSuspendedProcess,
            IntPtr hPrimaryToken,
            IntPtr hInitThread)
        {
            int nDosErrorCode;
            NTSTATUS ntstatus;
            var processAccessToken = new PROCESS_ACCESS_TOKEN
            {
                Token = hPrimaryToken,
                Thread = hInitThread
            };
            var nInfoLength = Marshal.SizeOf(processAccessToken);
            var pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
            Marshal.StructureToPtr(processAccessToken, pInfoBuffer, true);

            ntstatus = NativeMethods.NtSetInformationProcess(
                hSuspendedProcess,
                PROCESSINFOCLASS.ProcessAccessToken,
                pInfoBuffer,
                (uint)nInfoLength);
            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);
            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
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


        public static bool GetProcessUser(
            IntPtr hProcess,
            out string stringSid,
            out string accountName,
            out SID_NAME_USE sidType)
        {
            var bSuccess = false;
            NTSTATUS ntstatus = NativeMethods.NtOpenProcessToken(
                hProcess,
                ACCESS_MASK.TOKEN_QUERY,
                out IntPtr hToken);
            stringSid = null;
            accountName = null;
            sidType = SID_NAME_USE.Unknown;

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                bSuccess = GetTokenUser(hToken, out stringSid, out accountName, out sidType);
            }
            else
            {
                int nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
                NativeMethods.RtlSetLastWin32Error(nDosErrorCode);
            }

            return bSuccess;
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


        public static bool GetTokenUser(
            IntPtr hToken,
            out string stringSid,
            out string accountName,
            out SID_NAME_USE sidType)
        {
            int nDosErrorCode;
            var pInfoBuffer = Marshal.AllocHGlobal(0x400);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenUser,
                pInfoBuffer,
                0x100u,
                out uint _);
            stringSid = null;
            accountName = null;
            sidType = SID_NAME_USE.Unknown;
            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                bool bSuccess;
                long nAuthority = 0;
                var info = (TOKEN_USER)Marshal.PtrToStructure(pInfoBuffer, typeof(TOKEN_USER));
                var nSubAuthorityCount = (int)Marshal.ReadByte(info.User.Sid, 1);
                var stringSidBuilder = new StringBuilder("S-1");
                var nameBuilder = new StringBuilder(255);
                var domainBuilder = new StringBuilder(255);
                int nNameLength = 255;
                int nDomainLength = 255;

                for (int idx = 0; idx < 6; idx++)
                {
                    nAuthority <<= 8;
                    nAuthority |= (long)Marshal.ReadByte(info.User.Sid, 2 + idx);
                }

                stringSidBuilder.AppendFormat("-{0}", nAuthority);

                for (int idx = 0; idx < nSubAuthorityCount; idx++)
                    stringSidBuilder.AppendFormat("-{0}", (uint)Marshal.ReadInt32(info.User.Sid, 8 + (idx * 4)));

                stringSid = stringSidBuilder.ToString();
                bSuccess = NativeMethods.LookupAccountSid(
                    null,
                    info.User.Sid,
                    nameBuilder,
                    ref nNameLength,
                    domainBuilder,
                    ref nDomainLength,
                    out sidType);

                if (bSuccess)
                {
                    if ((nNameLength > 0) && (nDomainLength > 0))
                        accountName = string.Format(@"{0}\{1}", domainBuilder.ToString(), nameBuilder.ToString());
                    else if (nNameLength > 0)
                        accountName = nameBuilder.ToString();
                    else if (nDomainLength > 0)
                        accountName = domainBuilder.ToString();
                }
            }

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
    }
}
