using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using SystemServiceExec.Interop;

namespace SystemServiceExec.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        internal static bool AdjustTokenIntegrityLevel(
            IntPtr hToken,
            MANDATORY_LABEL_RID rid)
        {
            int nDosErrorCode;
            NTSTATUS ntstatus;
            IntPtr pSidBuffer;
            var nBaseSize = Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL));
            var nInfoLength = nBaseSize + 12;
            var pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);

            for (var oft = 0; oft < nInfoLength; oft++)
                Marshal.WriteByte(pInfoBuffer, oft, 0);

            if (Environment.Is64BitProcess)
                pSidBuffer = new IntPtr(pInfoBuffer.ToInt64() + nBaseSize);
            else
                pSidBuffer = new IntPtr(pInfoBuffer.ToInt32() + nBaseSize);

            Marshal.WriteIntPtr(pInfoBuffer, pSidBuffer);
            Marshal.WriteInt32(pInfoBuffer, IntPtr.Size, (int)SE_GROUP_ATTRIBUTES.Integrity);
            Marshal.WriteInt64(pSidBuffer, 0x1000000000000101);
            Marshal.WriteInt32(pSidBuffer, 8, (int)rid);

            ntstatus = NativeMethods.NtSetInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                pInfoBuffer,
                (uint)nInfoLength);

            Marshal.FreeHGlobal(pInfoBuffer);
            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        internal static string ConvertSidToStringSid(IntPtr pSid)
        {
            if (Marshal.ReadByte(pSid) != 1)
                return null;

            var sidBuilder = new StringBuilder("S-1");
            var nSubAuthorityCount = Marshal.ReadByte(pSid, 1);
            var nAuthority = 0u;

            for (int oft = 2; oft < 8; oft++)
            {
                nAuthority <<= 8;
                nAuthority |= (uint)Marshal.ReadByte(pSid, oft);
            }

            sidBuilder.AppendFormat("-{0}", nAuthority);

            for (int i = 0; i < nSubAuthorityCount; i++)
            {
                var nSubAuthority = (uint)Marshal.ReadInt32(pSid, 8 + (i * 4));
                sidBuilder.AppendFormat("-{0}", nSubAuthority);
            }

            return sidBuilder.ToString();
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
            else
                NativeMethods.RtlSetLastWin32Error(0); // ERROR_SUCCESS

            return nGuiSessionId;
        }


        internal static bool GetTokenIntegrityLevel(
            IntPtr hToken,
            out MANDATORY_LABEL_RID level)
        {
            int nDosErrorCode;
            var ntstatus = Win32Consts.STATUS_BUFFER_TOO_SMALL;
            var nInfoLength = 0x100u;
            var pInfoBuffer = IntPtr.Zero;
            level = MANDATORY_LABEL_RID.Untrust;

            while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL)
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Marshal.FreeHGlobal(pInfoBuffer);
                    pInfoBuffer = IntPtr.Zero;
                }
            }

            if (pInfoBuffer != IntPtr.Zero)
            {
                var info = (TOKEN_MANDATORY_LABEL)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(TOKEN_MANDATORY_LABEL));
                var pSid = info.Label.Sid;
                level = (MANDATORY_LABEL_RID)Marshal.ReadInt32(pSid, 8);
                Marshal.FreeHGlobal(pInfoBuffer);
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetTokenPrivileges(
            IntPtr hToken,
            out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> status)
        {
            int nDosErrorCode;
            var ntstatus = Win32Consts.STATUS_BUFFER_TOO_SMALL;
            var nInfoLength = 0x300u;
            var pInfoBuffer = IntPtr.Zero;
            status = new Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES>();

            while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL)
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenPrivileges,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Marshal.FreeHGlobal(pInfoBuffer);
                    pInfoBuffer = IntPtr.Zero;
                }
            }

            if (pInfoBuffer != IntPtr.Zero)
            {
                var nPrivOffset = Marshal.OffsetOf(typeof(TOKEN_PRIVILEGES), "Privileges").ToInt32();
                var nUnitSize = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
                var nAttrOffset = Marshal.OffsetOf(typeof(LUID_AND_ATTRIBUTES), "Attributes").ToInt32();
                var nCount = (uint)Marshal.ReadInt32(pInfoBuffer);

                for (var i = 0u; i < nCount; i++)
                {
                    var priv = (SE_PRIVILEGE_ID)Marshal.ReadInt64(pInfoBuffer, nPrivOffset);
                    var attr = (SE_PRIVILEGE_ATTRIBUTES)Marshal.ReadInt64(pInfoBuffer, nPrivOffset + nAttrOffset);
                    status.Add(priv, attr);
                    nPrivOffset += nUnitSize;
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool IsLocalAdminEnabledToken(IntPtr hToken)
        {
            int nDosErrorCode;
            var ntstatus = Win32Consts.STATUS_BUFFER_TOO_SMALL;
            // S-1-5-32-544: BUILTIN\Administrators
            var sidBytes = new byte[]
            {
                0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
                0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00
            };
            var nOffset = Marshal.OffsetOf(typeof(TOKEN_GROUPS), "Groups").ToInt32();
            var nUnitSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
            var nInfoLength = 0x200u;
            var pInfoBuffer = IntPtr.Zero;
            var bEnabled = false;

            while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL)
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenGroups,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Marshal.FreeHGlobal(pInfoBuffer);
                    pInfoBuffer = IntPtr.Zero;
                }
            }

            if (pInfoBuffer != IntPtr.Zero)
            {
                var nGroupCount = Marshal.ReadInt32(pInfoBuffer);

                for (var i = 0; i < nGroupCount; i++)
                {
                    var bIsLocalAdmin = false;
                    var pSid = Marshal.ReadIntPtr(
                        pInfoBuffer,
                        nOffset + (i * nUnitSize));

                    for (var oft = 0; oft < sidBytes.Length; oft++)
                    {
                        var b = Marshal.ReadByte(pSid, oft);
                        bIsLocalAdmin = (b == sidBytes[oft]);

                        if (!bIsLocalAdmin)
                            break;
                    }

                    if (bIsLocalAdmin)
                    {
                        var attr = (uint)Marshal.ReadInt32(
                            pInfoBuffer,
                            nOffset + (i * nUnitSize) + IntPtr.Size);
                        bEnabled = ((attr & (uint)SE_GROUP_ATTRIBUTES.Enabled) != 0);
                        break;
                    }
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return bEnabled;
        }


        public static bool IsSystemToken(IntPtr hToken)
        {
            int nDosErrorCode;
            var bIsSystemToken = false;
            var ntstatus = Win32Consts.STATUS_BUFFER_TOO_SMALL;
            // S-1-5-18: NT AUTHORITY\SYSTEM
            var sidBytes = new byte[]
            {
                0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
                0x12, 0x00, 0x00, 0x00
            };
            var nInfoLength = 0x100u;
            var pInfoBuffer = IntPtr.Zero;

            while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL)
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenUser,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Marshal.FreeHGlobal(pInfoBuffer);
                    pInfoBuffer = IntPtr.Zero;
                }
            }

            if (pInfoBuffer != IntPtr.Zero)
            {
                var info = (TOKEN_USER)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(TOKEN_USER));

                for (var oft = 0; oft < sidBytes.Length; oft++)
                {
                    var b = Marshal.ReadByte(info.User.Sid, oft);
                    bIsSystemToken = (b == sidBytes[oft]);

                    if (!bIsSystemToken)
                        break;
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return bIsSystemToken;
        }


        internal static void RevertToSelf()
        {
            var pInfoBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pInfoBuffer, IntPtr.Zero);
            NativeMethods.NtSetInformationThread(
                new IntPtr(-2),
                THREADINFOCLASS.ThreadImpersonationToken,
                pInfoBuffer,
                (uint)IntPtr.Size);
            Marshal.FreeHGlobal(pInfoBuffer);
        }


        public static bool SetAllTokenPrivileges(IntPtr hToken, bool bEnable)
        {
            int nDosErrorCode;
            var ntstatus = Win32Consts.STATUS_BUFFER_TOO_SMALL;
            var nInfoLength = 0x300u;
            var pInfoBuffer = IntPtr.Zero;

            while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL)
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenPrivileges,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Marshal.FreeHGlobal(pInfoBuffer);
                    pInfoBuffer = IntPtr.Zero;
                }
            }

            if (pInfoBuffer != IntPtr.Zero)
            {
                var nPrivOffset = Marshal.OffsetOf(typeof(TOKEN_PRIVILEGES), "Privileges").ToInt32();
                var nAttrOffset = Marshal.OffsetOf(typeof(LUID_AND_ATTRIBUTES), "Attributes").ToInt32();
                var nUnitSize = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
                var nCount = (uint)Marshal.ReadInt32(pInfoBuffer);

                for (var i = 0u; i < nCount; i++)
                {
                    var attr = Marshal.ReadInt32(pInfoBuffer, nPrivOffset + nAttrOffset);

                    if (bEnable)
                        attr |= (int)SE_PRIVILEGE_ATTRIBUTES.Enabled;
                    else
                        attr &= ~(int)SE_PRIVILEGE_ATTRIBUTES.Enabled;

                    Marshal.WriteInt32(pInfoBuffer, nPrivOffset + nAttrOffset, attr);
                    nPrivOffset += nUnitSize;
                }

                ntstatus = NativeMethods.NtAdjustPrivilegesToken(
                    hToken,
                    bEnable ? BOOLEAN.FALSE : BOOLEAN.TRUE,
                    pInfoBuffer,
                    (uint)nInfoLength,
                    IntPtr.Zero,
                    out uint _);
                Marshal.FreeHGlobal(pInfoBuffer);
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        internal static bool SetCurrentThreadToken(IntPtr hToken)
        {
            int nDosErrorCode;
            var pInfoBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenType,
                pInfoBuffer,
                4u,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var tokenType = (TOKEN_TYPE)Marshal.ReadInt32(pInfoBuffer);

                if (tokenType == TOKEN_TYPE.Primary)
                {
                    var objectAttributes = new OBJECT_ATTRIBUTES
                    {
                        Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
                    };
                    ntstatus = NativeMethods.NtDuplicateToken(
                        hToken,
                        ACCESS_MASK.TokenImpersonate | ACCESS_MASK.TokenQuery,
                        in objectAttributes,
                        BOOLEAN.FALSE,
                        TOKEN_TYPE.Impersonation,
                        out IntPtr hDupToken);

                    if (ntstatus == Win32Consts.STATUS_SUCCESS)
                    {
                        Marshal.WriteIntPtr(pInfoBuffer, hDupToken);
                        ntstatus = NativeMethods.NtSetInformationThread(
                            new IntPtr(-2),
                            THREADINFOCLASS.ThreadImpersonationToken,
                            pInfoBuffer,
                            (uint)IntPtr.Size);
                        NativeMethods.NtClose(hDupToken);
                    }
                }
                else
                {
                    Marshal.WriteIntPtr(pInfoBuffer, hToken);
                    ntstatus = NativeMethods.NtSetInformationThread(
                        new IntPtr(-2),
                        THREADINFOCLASS.ThreadImpersonationToken,
                        pInfoBuffer,
                        (uint)IntPtr.Size);
                }
            }

            Marshal.FreeHGlobal(pInfoBuffer);
            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool SetMultipleTokenPrivileges(
            IntPtr hToken,
            Dictionary<SE_PRIVILEGE_ID, bool> privs)
        {
            int nDosErrorCode;
            var nAvailableCount = 0;
            var ntstatus = Win32Consts.STATUS_NOT_ALL_ASSIGNED;
            var availabilities = new Dictionary<SE_PRIVILEGE_ID, bool>();
            var bSuccess = GetTokenPrivileges(
                hToken,
                out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> status);

            foreach (var p in privs.Keys)
                availabilities.Add(p, false);

            if (!bSuccess)
                return false;

            foreach (var p in privs.Keys)
            {
                if (status.ContainsKey(p))
                {
                    availabilities[p] = true;
                    nAvailableCount++;
                }
            }

            if (nAvailableCount > 0)
            {
                var nPrivOffset = Marshal.OffsetOf(typeof(TOKEN_PRIVILEGES), "Privileges").ToInt32();
                var nAttrOffset = Marshal.OffsetOf(typeof(LUID_AND_ATTRIBUTES), "Attributes").ToInt32();
                var nUnitSize = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
                var nInfoLength = Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)) +
                    (Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES)) * (nAvailableCount - 1));
                var pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);

                for (var oft = 0; oft < nInfoLength; oft++)
                    Marshal.WriteByte(pInfoBuffer, oft, 0);

                Marshal.WriteInt32(pInfoBuffer, nAvailableCount);

                foreach (var p in availabilities)
                {
                    Marshal.WriteInt64(pInfoBuffer, nPrivOffset, (long)p.Key);

                    if (privs[p.Key])
                        Marshal.WriteInt32(pInfoBuffer, nPrivOffset + nAttrOffset, (int)SE_PRIVILEGE_ATTRIBUTES.Enabled);

                    nPrivOffset += nUnitSize;
                }

                ntstatus = NativeMethods.NtAdjustPrivilegesToken(
                    hToken,
                    BOOLEAN.FALSE,
                    pInfoBuffer,
                    (uint)nInfoLength,
                    IntPtr.Zero,
                    out uint _);

                if (nAvailableCount != privs.Count)
                    ntstatus = Win32Consts.STATUS_NOT_ALL_ASSIGNED;
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool SetSingleTokenPrivilege(
            IntPtr hToken,
            SE_PRIVILEGE_ID priv,
            bool bEnable)
        {
            int nDosErrorCode;
            IntPtr pInfoBuffer;
            bool bAvailable = false;
            var ntstatus = Win32Consts.STATUS_NO_SUCH_PRIVILEGE;
            var nPrivOffset = Marshal.OffsetOf(typeof(TOKEN_PRIVILEGES), "Privileges").ToInt32();
            var nAttrOffset = Marshal.OffsetOf(typeof(LUID_AND_ATTRIBUTES), "Attributes").ToInt32();
            var nAttrValue = bEnable ? (int)SE_PRIVILEGE_ATTRIBUTES.Enabled : (int)SE_PRIVILEGE_ATTRIBUTES.Disabled;
            var nInfoLength = Marshal.SizeOf(typeof(TOKEN_PRIVILEGES));
            var bSuccess = GetTokenPrivileges(
                hToken,
                out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> status);

            if (!bSuccess)
                return false;

            foreach (var p in status)
            {
                if (p.Key == priv)
                {
                    bAvailable = true;
                    break;
                }
            }

            if (bAvailable)
            {
                pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);

                for (var oft = 0; oft < nInfoLength; oft++)
                    Marshal.WriteByte(pInfoBuffer, oft, 0);

                Marshal.WriteInt32(pInfoBuffer, 1);
                Marshal.WriteInt64(pInfoBuffer, nPrivOffset, (long)priv);
                Marshal.WriteInt32(pInfoBuffer, nPrivOffset + nAttrOffset, nAttrValue);

                ntstatus = NativeMethods.NtAdjustPrivilegesToken(
                    hToken,
                    BOOLEAN.FALSE,
                    pInfoBuffer,
                    (uint)nInfoLength,
                    IntPtr.Zero,
                    out uint _);

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool SetTokenSessionId(IntPtr hToken, int nSessionId)
        {
            int nDosErrorCode;
            NTSTATUS ntstatus;
            var nInfoLength = Marshal.SizeOf(typeof(int));
            var pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
            Marshal.WriteInt32(pInfoBuffer, nSessionId);

            ntstatus = NativeMethods.NtSetInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenSessionId,
                pInfoBuffer,
                (uint)nInfoLength);

            Marshal.FreeHGlobal(pInfoBuffer);
            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }
    }
}
