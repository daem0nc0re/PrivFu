using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using SwitchPriv.Interop;

namespace SwitchPriv.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static bool DisableTokenPrivileges(
            IntPtr hToken,
            in List<SE_PRIVILEGE_ID> privsToDisable,
            out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs)
        {
            bool bAllDisabled;
            int nDosErrorCode;
            IntPtr pInfoBuffer;
            NTSTATUS nErrorStatus = Win32Consts.STATUS_SUCCESS;
            adjustedPrivs = new Dictionary<SE_PRIVILEGE_ID, bool>();

            foreach (var id in privsToDisable)
                adjustedPrivs.Add(id, false);

            if (privsToDisable.Count == 0)
                return true;

            bAllDisabled = Helpers.GetTokenPrivileges(
                hToken,
                out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

            if (!bAllDisabled)
                return false;

            pInfoBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));

            foreach (var priv in privsToDisable)
            {
                NTSTATUS ntstatus;
                var info = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new LUID_AND_ATTRIBUTES[1]
                };

                if (!availablePrivs.ContainsKey(priv))
                    continue;

                if ((availablePrivs[priv] & SE_PRIVILEGE_ATTRIBUTES.Enabled) == 0)
                    continue;

                info.Privileges[0].Luid.QuadPart = (long)priv;
                Marshal.StructureToPtr(info, pInfoBuffer, true);
                ntstatus = NativeMethods.NtAdjustPrivilegesToken(
                    hToken,
                    BOOLEAN.TRUE,
                    pInfoBuffer,
                    (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)),
                    IntPtr.Zero,
                    out uint _);
                adjustedPrivs[priv] = !(ntstatus == Win32Consts.STATUS_SUCCESS);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    nErrorStatus = ntstatus;
                    bAllDisabled = false;
                }
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(nErrorStatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);
            Marshal.FreeHGlobal(pInfoBuffer);

            return bAllDisabled;
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

            bAllEnabled = Helpers.GetTokenPrivileges(
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


        public static bool ImpersonateAsSmss()
        {
            int nSmssId;
            IntPtr hToken;
            var bSuccess = false;
            var requiredPrivs = new List<SE_PRIVILEGE_ID> { SE_PRIVILEGE_ID.SeDebugPrivilege };

            try
            {
                nSmssId = Process.GetProcessesByName("smss")[0].Id;
            }
            catch
            {
                NativeMethods.RtlSetLastWin32Error(5); // ERROR_ACCESS_DENIED
                return false;
            }

            hToken = Helpers.GetProcessToken(nSmssId, TOKEN_TYPE.Impersonation);

            if (hToken != IntPtr.Zero)
            {
                EnableTokenPrivileges(in requiredPrivs, out Dictionary<SE_PRIVILEGE_ID, bool> _);
                bSuccess = Helpers.ImpersonateThreadToken(new IntPtr(-2), hToken);
                NativeMethods.NtClose(hToken);
            }

            return bSuccess;
        }


        public static bool RemoveTokenPrivileges(
            IntPtr hToken,
            in List<SE_PRIVILEGE_ID> privsToRemove,
            out Dictionary<SE_PRIVILEGE_ID, bool> removedStatus)
        {
            bool bAllRemoved;
            int nDosErrorCode;
            IntPtr pInfoBuffer;
            NTSTATUS nErrorStatus = Win32Consts.STATUS_SUCCESS;
            removedStatus = new Dictionary<SE_PRIVILEGE_ID, bool>();

            foreach (var id in privsToRemove)
                removedStatus.Add(id, false);

            if (privsToRemove.Count == 0)
                return true;

            bAllRemoved = Helpers.GetTokenPrivileges(
                hToken,
                out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

            if (!bAllRemoved)
                return false;

            pInfoBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));

            foreach (var priv in privsToRemove)
            {
                NTSTATUS ntstatus;
                var info = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new LUID_AND_ATTRIBUTES[1]
                };

                if (!availablePrivs.ContainsKey(priv))
                {
                    removedStatus[priv] = true;
                    continue;
                }

                info.Privileges[0].Luid.QuadPart = (long)priv;
                info.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.Removed;
                Marshal.StructureToPtr(info, pInfoBuffer, true);
                ntstatus = NativeMethods.NtAdjustPrivilegesToken(
                    hToken,
                    BOOLEAN.FALSE,
                    pInfoBuffer,
                    (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)),
                    IntPtr.Zero,
                    out uint _);
                removedStatus[priv] = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    nErrorStatus = ntstatus;
                    bAllRemoved = false;
                }
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(nErrorStatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);
            Marshal.FreeHGlobal(pInfoBuffer);

            return bAllRemoved;
        }


        public static IntPtr OpenProcessToken(int pid, ACCESS_MASK tokenAccessMask)
        {
            int nDosErrorCode;
            var hToken = IntPtr.Zero;
            var objectAttrbutes = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
            };
            var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(pid) };
            NTSTATUS ntstatus = NativeMethods.NtOpenProcess(
                out IntPtr hProcess,
                ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                in objectAttrbutes,
                in clientId);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                ntstatus = NativeMethods.NtOpenProcessToken(
                    hProcess,
                    tokenAccessMask,
                    out hToken);
                NativeMethods.NtClose(hProcess);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    hToken = IntPtr.Zero;
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return hToken;
        }


        public static int ResolveProcessId(int pid, out string processName)
        {
            processName = null;

            if (pid == -1)
            {
                pid = Helpers.GetParentProcessId(new IntPtr(-1));
            }
            else
            {
                try
                {
                    processName = Process.GetProcessById(pid).ProcessName;
                }
                catch
                {
                    pid = -1;
                    processName = null;
                }
            }

            return pid;
        }


        public static bool SetMandatoryLevel(IntPtr hToken, int rid)
        {
            int nDosErrorCode;
            NTSTATUS ntstatus;
            var labelBytes = new byte[] { 1, 1, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0 };
            var nInfoLength = Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL)) + labelBytes.Length;
            var pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
            var info = new TOKEN_MANDATORY_LABEL
            {
                Label = new SID_AND_ATTRIBUTES()
            };
            info.Label.Attributes = (uint)(SE_GROUP_ATTRIBUTES.Integrity);

            if (Environment.Is64BitProcess)
                info.Label.Sid = new IntPtr(pInfoBuffer.ToInt64() + Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL)));
            else
                info.Label.Sid = new IntPtr(pInfoBuffer.ToInt32() + Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL)));

            Marshal.StructureToPtr(info, pInfoBuffer, true);
            Marshal.Copy(labelBytes, 0, info.Label.Sid, labelBytes.Length);
            Marshal.WriteInt32(info.Label.Sid, 8, rid);
            ntstatus = NativeMethods.NtSetInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                pInfoBuffer,
                (uint)nInfoLength);
            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);
            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }
    }
}
