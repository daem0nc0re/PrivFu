using System;
using System.Runtime.InteropServices;
using DesktopShell.Interop;

namespace DesktopShell.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {

        public static bool EnableSeTcbPrivilege()
        {
            NTSTATUS ntstatus;
            int nDosErrorCode;
            var nOffset = Marshal.OffsetOf(typeof(TOKEN_PRIVILEGES), "Privileges").ToInt32();
            var nInfoLength = (uint)(nOffset + Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES)) * 36);
            var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            var bEnabled = false;

            do
            {
                int nPrivilegeCount;
                var bPresent = false;
                ntstatus = NativeMethods.NtOpenProcessToken(
                    new IntPtr(-1),
                    ACCESS_MASK.TOKEN_ADJUST_PRIVILEGES | ACCESS_MASK.TOKEN_QUERY,
                    out IntPtr hToken);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenPrivileges,
                    pInfoBuffer,
                    nInfoLength,
                    out uint _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    NativeMethods.NtClose(hToken);
                    break;
                }

                nPrivilegeCount = Marshal.ReadInt32(pInfoBuffer);

                for (var idx = 0; idx < nPrivilegeCount; idx++)
                {
                    var priv = Marshal.ReadInt64(pInfoBuffer, nOffset);
                    var attr = Marshal.ReadInt32(pInfoBuffer, nOffset + 8);

                    if (priv == Win32Consts.SE_TCB_PRIVILEGE.ToInt64())
                    {
                        bPresent = true;
                        bEnabled = (((int)SE_PRIVILEGE_ATTRIBUTES.Enabled & attr) != 0);
                    }

                    nOffset += Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
                }

                if (bPresent && !bEnabled)
                {
                    var info = new TOKEN_PRIVILEGES
                    {
                        PrivilegeCount = 1,
                        Privileges = new LUID_AND_ATTRIBUTES[1]
                    };
                    info.Privileges[0].Luid = Win32Consts.SE_TCB_PRIVILEGE;
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
                else if (!bPresent)
                {
                    ntstatus = Win32Consts.STATUS_PRIVILEGE_NOT_HELD;
                }

                NativeMethods.NtClose(hToken);
            } while (false);

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);
            Marshal.FreeHGlobal(pInfoBuffer);

            return bEnabled;
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
    }
}
