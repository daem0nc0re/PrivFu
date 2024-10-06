using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using BackgroundShell.Interop;

namespace BackgroundShell.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static bool EnableTokenPrivileges(
            in List<SE_PRIVILEGE_ID> requiredPrivs,
            out Dictionary<SE_PRIVILEGE_ID, bool> privStates)
        {
            bool bAllEnabled = false;
            NTSTATUS ntstatus = NativeMethods.NtOpenProcessToken(
                new IntPtr(-1),
                ACCESS_MASK.TOKEN_ADJUST_PRIVILEGES | ACCESS_MASK.TOKEN_QUERY,
                out IntPtr hToken);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                bAllEnabled = EnableTokenPrivileges(
                    hToken,
                    in requiredPrivs,
                    out privStates);
                NativeMethods.NtClose(hToken);
            }
            else
            {
                privStates = new Dictionary<SE_PRIVILEGE_ID, bool>();

                foreach (var id in requiredPrivs)
                    privStates.Add(id, false);
            }

            return bAllEnabled;
        }


        public static bool EnableTokenPrivileges(
            IntPtr hToken,
            in List<SE_PRIVILEGE_ID> requiredPrivs,
            out Dictionary<SE_PRIVILEGE_ID, bool> privStates)
        {
            NTSTATUS ntstatus;
            var nOffset = Marshal.OffsetOf(typeof(TOKEN_PRIVILEGES), "Privileges").ToInt32();
            var nInfoLength = (uint)(nOffset + Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES)) * 36);
            var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            var bAllEnabled = true;
            privStates = new Dictionary<SE_PRIVILEGE_ID, bool>();

            foreach (var id in requiredPrivs)
                privStates.Add(id, false);

            do
            {
                int nPrivilegeCount;
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenPrivileges,
                    pInfoBuffer,
                    nInfoLength,
                    out uint _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                nPrivilegeCount = Marshal.ReadInt32(pInfoBuffer);

                for (var idx = 0; idx < nPrivilegeCount; idx++)
                {
                    var priv = Marshal.ReadInt64(pInfoBuffer, nOffset);
                    var attr = Marshal.ReadInt32(pInfoBuffer, nOffset + 8);

                    foreach (var id in requiredPrivs)
                    {
                        bool bEnabled = false;

                        if (priv == (long)id)
                        {
                            bEnabled = (((int)SE_PRIVILEGE_ATTRIBUTES.Enabled & attr) != 0);

                            if (!bEnabled)
                            {
                                var info = new TOKEN_PRIVILEGES
                                {
                                    PrivilegeCount = 1,
                                    Privileges = new LUID_AND_ATTRIBUTES[1]
                                };
                                info.Privileges[0].Luid.QuadPart = (long)id;
                                info.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.Enabled;
                                Marshal.StructureToPtr(info, pInfoBuffer, true);

                                ntstatus = NativeMethods.NtAdjustPrivilegesToken(
                                    hToken,
                                    BOOLEAN.FALSE,
                                    pInfoBuffer,
                                    (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)),
                                    IntPtr.Zero,
                                    out uint _);
                                bEnabled = (ntstatus == Win32Consts.STATUS_SUCCESS);
                            }

                            if (bEnabled)
                                privStates[id] = true;
                        }
                    }

                    nOffset += Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
                }
            } while (false);

            Marshal.FreeHGlobal(pInfoBuffer);

            foreach (var status in privStates.Values)
            {
                if (!status)
                {
                    NativeMethods.RtlSetLastWin32Error(Win32Consts.ERROR_PRIVILEGE_NOT_HELD);
                    bAllEnabled = false;
                    break;
                }
            }

            return bAllEnabled;
        }


        public static int GetTokenSessionId(IntPtr hToken)
        {
            int nSessionId = -1;
            var pInfoBuffer = Marshal.AllocHGlobal(4);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenSessionId,
                pInfoBuffer,
                4u,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
                nSessionId = Marshal.ReadInt32(pInfoBuffer);

            Marshal.FreeHGlobal(pInfoBuffer);
            ntstatus = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(ntstatus);

            return nSessionId;
        }


        public static IntPtr GetWinlogonToken(TOKEN_TYPE tokenType)
        {
            NTSTATUS ntstatus;
            IntPtr pContextBuffer;
            int nContextSize = Marshal.SizeOf(typeof(SECURITY_QUALITY_OF_SERVICE));
            var hDupToken = IntPtr.Zero;
            var clientId = new CLIENT_ID();
            var objectAttributes = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
            };
            var context = new SECURITY_QUALITY_OF_SERVICE
            {
                Length = nContextSize,
                ImpersonationLevel = SECURITY_IMPERSONATION_LEVEL.Impersonation
            };

            try
            {
                int nWinlogonId = Process.GetProcessesByName("winlogon")[0].Id;
                clientId.UniqueProcess = new IntPtr(nWinlogonId);
            }
            catch
            {
                NativeMethods.RtlSetLastWin32Error(5); // ERROR_ACCESS_DENIED
                return IntPtr.Zero;
            }

            pContextBuffer = Marshal.AllocHGlobal(nContextSize);
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


        public static bool SetTokenSessionId(IntPtr hToken, int nSessionId)
        {
            int nDosErrorCode;
            var pInfoBuffer = Marshal.AllocHGlobal(4);
            Marshal.WriteInt32(pInfoBuffer, nSessionId);
            NTSTATUS ntstatus = NativeMethods.NtSetInformationToken(
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
