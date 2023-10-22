using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using WfpTokenDup.Interop;

namespace WfpTokenDup.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        public static bool ConvertStringToSockAddr(
            string addressString,
            out SOCKADDR sockAddr)
        {
            int nReturnCode;
            var nInfoLength = Marshal.SizeOf(typeof(SOCKADDR));
            var pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);

            nReturnCode = NativeMethods.WSAStringToAddressW(
                addressString,
                (int)ADDRESS_FAMILY.AF_INET,
                IntPtr.Zero,
                pInfoBuffer,
                ref nInfoLength);

            if (nReturnCode != 0)
                ZeroMemory(pInfoBuffer, nInfoLength);

            sockAddr = (SOCKADDR)Marshal.PtrToStructure(pInfoBuffer, typeof(SOCKADDR));
            Marshal.FreeHGlobal(pInfoBuffer);

            return (nReturnCode == 0);
        }


        public static bool EnumerateSessionLuids(out List<LUID> sessionLuids)
        {
            NTSTATUS ntstatus = NativeMethods.LsaEnumerateLogonSessions(
                out uint nLogonSessionCount,
                out IntPtr pLogonSessionList);
            sessionLuids = new List<LUID>();

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                for (var idx = 0; idx < (int)nLogonSessionCount; idx++)
                    sessionLuids.Add(LUID.FromInt64(Marshal.ReadInt64(pLogonSessionList, idx * 8)));
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static string GetObjectName(IntPtr hObject)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            string objectName = null;
            var nInfoLength = (uint)0x400;

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryObject(
                    hObject,
                    OBJECT_INFORMATION_CLASS.ObjectNameInformation,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_INFO_LENGTH_MISMATCH);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var nameInfo = (OBJECT_NAME_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(OBJECT_NAME_INFORMATION));
                objectName = nameInfo.Name.ToString();
                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return objectName;
        }


        public static int GetObjectTypeIndex(string typeName)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoSize = (uint)Marshal.SizeOf(typeof(OBJECT_TYPES_INFORMATION));
            var typeIndex = -1;

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoSize);
                ntstatus = NativeMethods.NtQueryObject(
                    IntPtr.Zero,
                    OBJECT_INFORMATION_CLASS.ObjectTypesInformation,
                    pInfoBuffer,
                    nInfoSize,
                    out nInfoSize);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_INFO_LENGTH_MISMATCH);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                IntPtr pEntry;
                var nEntryCount = Marshal.ReadInt32(pInfoBuffer);

                if (Environment.Is64BitProcess)
                    pEntry = new IntPtr(pInfoBuffer.ToInt64() + IntPtr.Size);
                else
                    pEntry = new IntPtr(pInfoBuffer.ToInt32() + IntPtr.Size);

                for (var idx = 0; idx < nEntryCount; idx++)
                {
                    var entry = (OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(
                        pEntry,
                        typeof(OBJECT_TYPE_INFORMATION));
                    var nNextOffset = Marshal.SizeOf(typeof(OBJECT_TYPE_INFORMATION));
                    nNextOffset += entry.TypeName.MaximumLength;

                    if ((nNextOffset % IntPtr.Size) > 0)
                        nNextOffset += (IntPtr.Size - (nNextOffset % IntPtr.Size));

                    if (CompareIgnoreCase(entry.TypeName.ToString(), typeName))
                    {
                        typeIndex = (int)entry.TypeIndex;
                        break;
                    }

                    if (Environment.Is64BitProcess)
                        pEntry = new IntPtr(pEntry.ToInt64() + nNextOffset);
                    else
                        pEntry = new IntPtr(pEntry.ToInt32() + nNextOffset);
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return typeIndex;
        }


        public static bool GetProcessHandles(
            int pid,
            out List<SYSTEM_HANDLE_TABLE_ENTRY_INFO> handles)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoSize = (uint)Marshal.SizeOf(typeof(SYSTEM_HANDLE_INFORMATION));
            handles = new List<SYSTEM_HANDLE_TABLE_ENTRY_INFO>();

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoSize);
                ntstatus = NativeMethods.NtQuerySystemInformation(
                    SYSTEM_INFORMATION_CLASS.SystemHandleInformation,
                    pInfoBuffer,
                    nInfoSize,
                    out nInfoSize);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_INFO_LENGTH_MISMATCH);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                IntPtr pEntry;
                var nEntrySize = Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
                var nEntryOffset = Marshal.OffsetOf(typeof(SYSTEM_HANDLE_INFORMATION), "Handles").ToInt32();
                var nEntryCount = Marshal.ReadInt32(pInfoBuffer);

                for (var idx = 0; idx < nEntryCount; idx++)
                {
                    if (Environment.Is64BitProcess)
                        pEntry = new IntPtr(pInfoBuffer.ToInt64() + nEntryOffset + (nEntrySize * idx));
                    else
                        pEntry = new IntPtr(pInfoBuffer.ToInt32() + nEntryOffset + (nEntrySize * idx));

                    var entry = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)Marshal.PtrToStructure(
                        pEntry,
                        typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));

                    if ((int)entry.UniqueProcessId == pid)
                        handles.Add(entry);
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static int GetServicePid(string serviceName)
        {
            IntPtr hSCManager;
            var hService = IntPtr.Zero;
            int pid = -1;

            do
            {
                IntPtr pInfoBuffer;
                var nInfoLength = Marshal.SizeOf(typeof(SERVICE_STATUS_PROCESS));
                hSCManager = NativeMethods.OpenSCManager(null, null, ACCESS_MASK.SC_MANAGER_CONNECT);

                if (hSCManager == IntPtr.Zero)
                    break;

                hService = NativeMethods.OpenService(hSCManager, serviceName, ACCESS_MASK.SERVICE_QUERY_STATUS);

                if (hSCManager == IntPtr.Zero)
                    break;

                pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);

                if (NativeMethods.QueryServiceStatusEx(
                    hService,
                    SC_STATUS_TYPE.PROCESS_INFO,
                    pInfoBuffer,
                    nInfoLength,
                    out int _))
                {
                    var info = (SERVICE_STATUS_PROCESS)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(SERVICE_STATUS_PROCESS));
                    pid = info.dwProcessId;
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            } while (false);

            if (hService != IntPtr.Zero)
                NativeMethods.CloseServiceHandle(hService);

            if (hSCManager != IntPtr.Zero)
                NativeMethods.CloseServiceHandle(hSCManager);

            return pid;
        }


        public static int GetServicePidBySession(string serviceName, int sessionId)
        {
            IntPtr hSCManager;
            var hService = IntPtr.Zero;
            int pid = -1;

            do
            {
                IntPtr pInfoBuffer;
                hSCManager = NativeMethods.OpenSCManager(null, null, ACCESS_MASK.SC_MANAGER_ENUMERATE_SERVICE);

                if (hSCManager == IntPtr.Zero)
                    break;

                NativeMethods.EnumServicesStatus(
                    hSCManager,
                    SERVICE_TYPE.WIN32_SHARE_PROCESS,
                    SERVICE_CONTROL_STATE.ACTIVE,
                    IntPtr.Zero,
                    0,
                    out int nInfoLength,
                    out int _,
                    IntPtr.Zero);

                pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);

                if (NativeMethods.EnumServicesStatus(
                    hSCManager,
                    SERVICE_TYPE.WIN32_SHARE_PROCESS,
                    SERVICE_CONTROL_STATE.ACTIVE,
                    pInfoBuffer,
                    nInfoLength,
                    out int _,
                    out int nServiceCount,
                    IntPtr.Zero))
                {
                    for (var idx = 0; idx < nServiceCount; idx++)
                    {
                        IntPtr pEntry;
                        int servicePid;

                        if (Environment.Is64BitProcess)
                            pEntry = new IntPtr(pInfoBuffer.ToInt64() + (Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS)) * idx));
                        else
                            pEntry = new IntPtr(pInfoBuffer.ToInt32() + (Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS)) * idx));

                        var info = (ENUM_SERVICE_STATUS)Marshal.PtrToStructure(
                            pEntry,
                            typeof(ENUM_SERVICE_STATUS));

                        if (info.lpServiceName.IndexOf(
                            serviceName,
                            StringComparison.OrdinalIgnoreCase) < 0)
                        {
                            continue;
                        }

                        servicePid = GetServicePid(info.lpServiceName);

                        if (servicePid == -1)
                            continue;

                        if (NativeMethods.ProcessIdToSessionId(servicePid, out int serviceSessionId))
                        {
                            if (sessionId == serviceSessionId)
                            {
                                pid = servicePid;
                                break;
                            }
                        }
                    }
                }
            } while (false);

            if (hService != IntPtr.Zero)
                NativeMethods.CloseServiceHandle(hService);

            if (hSCManager != IntPtr.Zero)
                NativeMethods.CloseServiceHandle(hSCManager);

            return pid;
        }


        public static string GetSessionAccountName(int sessionId)
        {
            string accountName = null;

            do
            {
                string domainName = null;
                string userName = null;
                var status = NativeMethods.WTSQuerySessionInformation(
                    Win32Consts.WTS_CURRENT_SERVER_HANDLE,
                    sessionId,
                    WTS_INFO_CLASS.WTSDomainName,
                    out IntPtr pDomainName,
                    out int nDomainNameLength);

                if (!status)
                    break;

                if (nDomainNameLength > 2)
                    domainName = Marshal.PtrToStringUni(pDomainName, nDomainNameLength / 2);

                if (nDomainNameLength > 0)
                    NativeMethods.WTSFreeMemory(pDomainName);

                status = NativeMethods.WTSQuerySessionInformation(
                    Win32Consts.WTS_CURRENT_SERVER_HANDLE,
                    sessionId,
                    WTS_INFO_CLASS.WTSUserName,
                    out IntPtr pUserName,
                    out int nUserNameLength);

                if (!status)
                    break;

                if (nUserNameLength > 2)
                    userName = Marshal.PtrToStringUni(pUserName, nUserNameLength / 2);

                if (nUserNameLength > 0)
                    NativeMethods.WTSFreeMemory(pUserName);

                if ((nDomainNameLength > 2) && (nUserNameLength > 2))
                    accountName = string.Format(@"{0}\{1}", domainName, userName);
                else if (nDomainNameLength > 2)
                    accountName = domainName;
                else if (nUserNameLength > 2)
                    accountName = userName;
            } while (false);

            return accountName;
        }


        public static bool GetSessionBasicInformation(
            in LUID sessionLuid,
            out string accountName,
            out string accountSid,
            out string authPackage)
        {
            NTSTATUS ntstatus = NativeMethods.LsaGetLogonSessionData(
                in sessionLuid,
                out IntPtr pInfoBuffer);
            accountName = null;
            accountSid = null;
            authPackage = null;

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var info = (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(SECURITY_LOGON_SESSION_DATA));

                if ((info.UserName.Length > 0) && (info.LogonDomain.Length > 0))
                    accountName = string.Format(@"{0}\{1}", info.LogonDomain.ToString(), info.UserName.ToString());
                else if (info.UserName.Length > 0)
                    accountName = info.UserName.ToString();
                else if (info.LogonDomain.Length > 0)
                    accountName = info.LogonDomain.ToString();

                if (info.Sid != IntPtr.Zero)
                    NativeMethods.ConvertSidToStringSid(info.Sid, out accountSid);

                if (info.AuthenticationPackage.Length > 0)
                    authPackage = info.AuthenticationPackage.ToString();

                NativeMethods.LsaFreeReturnBuffer(pInfoBuffer);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetTokenPrivileges(
            IntPtr hToken,
            out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> privileges)
        {
            NTSTATUS ntstatus;
            IntPtr pInformationBuffer;
            var nInformationLength = (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES));
            privileges = new Dictionary<string, SE_PRIVILEGE_ATTRIBUTES>();

            do
            {
                pInformationBuffer = Marshal.AllocHGlobal((int)nInformationLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenPrivileges,
                    pInformationBuffer,
                    nInformationLength,
                    out nInformationLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInformationBuffer);
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var tokenPrivileges = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(
                    pInformationBuffer,
                    typeof(TOKEN_PRIVILEGES));
                var nEntryOffset = Marshal.OffsetOf(typeof(TOKEN_PRIVILEGES), "Privileges").ToInt32();
                var nUnitSize = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));

                for (var idx = 0; idx < tokenPrivileges.PrivilegeCount; idx++)
                {
                    int cchName = 128;
                    var stringBuilder = new StringBuilder(cchName);
                    var luid = LUID.FromInt64(Marshal.ReadInt64(pInformationBuffer, nEntryOffset + (nUnitSize * idx)));
                    var nAttributesOffset = Marshal.OffsetOf(typeof(LUID_AND_ATTRIBUTES), "Attributes").ToInt32();
                    var attributes = (SE_PRIVILEGE_ATTRIBUTES)Marshal.ReadInt32(
                        pInformationBuffer,
                        nEntryOffset + (nUnitSize * idx) + nAttributesOffset);

                    NativeMethods.LookupPrivilegeName(null, in luid, stringBuilder, ref cchName);
                    privileges.Add(stringBuilder.ToString(), attributes);
                    stringBuilder.Clear();
                }

                Marshal.FreeHGlobal(pInformationBuffer);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static int GetTokenSessionId(IntPtr hToken)
        {
            int sessionId = -1;
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(4);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenSessionId,
                pInfoBuffer,
                4u,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
                sessionId = Marshal.ReadInt32(pInfoBuffer);

            Marshal.FreeHGlobal(pInfoBuffer);

            return sessionId;
        }


        public static string GetTokenSessionSid(IntPtr hToken)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            string stringSid = null;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_GROUPS));

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenLogonSid,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                if (Marshal.ReadInt32(pInfoBuffer) > 0)
                {
                    var status = NativeMethods.ConvertSidToStringSid(
                        Marshal.ReadIntPtr(pInfoBuffer, IntPtr.Size),
                        out stringSid);

                    if (!status)
                        stringSid = null;
                }
            }

            return stringSid;
        }


        public static string GetTokenUserSid(IntPtr hToken)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            string stringSid = null;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_USER));

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenUser,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                NativeMethods.ConvertSidToStringSid(Marshal.ReadIntPtr(pInfoBuffer), out stringSid);
                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return stringSid;
        }


        public static bool SetTokenLogonSid(IntPtr hToken, string stringSid)
        {
            if (!stringSid.StartsWith("S-1-5-5", StringComparison.OrdinalIgnoreCase))
                return false;

            if (!NativeMethods.ConvertStringSidToSid(stringSid, out IntPtr pSid))
                return false;

            bool status = SetTokenLogonSid(hToken, pSid);
            NativeMethods.LocalFree(pSid);

            return status;
        }

        public static bool SetTokenLogonSid(IntPtr hToken, IntPtr pSid)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_GROUPS));

            if ((Marshal.ReadByte(pSid) != 1) ||
                (Marshal.ReadInt16(pSid, 2) != 0) ||
                (Marshal.ReadInt32(pSid, 4) != 0x05000000) ||
                (Marshal.ReadInt32(pSid, 8) != 5))
            {
                return false;
            }

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
                IntPtr pUpdatedGroups;
                var isUpdated = false;
                var nUnitSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
                var nGroupCount = Marshal.ReadInt32(pInfoBuffer);

                for (var idx = 0; idx < nGroupCount; idx++)
                {
                    var sidAttributes = (SE_GROUP_ATTRIBUTES)Marshal.ReadInt32(pInfoBuffer, (IntPtr.Size * 2) + (nUnitSize * idx));

                    if ((sidAttributes & SE_GROUP_ATTRIBUTES.LogonId) != 0)
                    {
                        Marshal.WriteIntPtr(pInfoBuffer, IntPtr.Size + (nUnitSize * idx), pSid);
                        isUpdated = true;
                        break;
                    }
                }

                if (!isUpdated)
                {
                    var groupAttributes = (int)(SE_GROUP_ATTRIBUTES.Enabled &
                        SE_GROUP_ATTRIBUTES.EnabledByDefault &
                        SE_GROUP_ATTRIBUTES.LogonId &
                        SE_GROUP_ATTRIBUTES.Mandatory);
                    pUpdatedGroups = Marshal.AllocHGlobal((int)nInfoLength + nUnitSize);

                    for (var idx = 0; idx < (int)nInfoLength; idx++)
                        Marshal.WriteByte(pUpdatedGroups, idx, Marshal.ReadByte(pInfoBuffer, idx));

                    for (var idx = 0; idx < nUnitSize; idx++)
                        Marshal.WriteByte(pUpdatedGroups, (int)nInfoLength + idx, 0);

                    Marshal.WriteIntPtr(pUpdatedGroups, (int)nInfoLength, pSid);
                    Marshal.WriteInt32(pUpdatedGroups, (int)nInfoLength + IntPtr.Size, groupAttributes);
                    nInfoLength += (uint)nUnitSize;
                }
                else
                {
                    pUpdatedGroups = pInfoBuffer;
                }

                ntstatus = NativeMethods.NtSetInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenGroups,
                    pUpdatedGroups,
                    nInfoLength);

                if (pUpdatedGroups != pInfoBuffer)
                    Marshal.FreeHGlobal(pUpdatedGroups);

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static void WriteGuidToPointer(IntPtr pBuffer, in Guid guid)
        {
            WriteGuidToPointer(pBuffer, 0, in guid);
        }


        public static void WriteGuidToPointer(IntPtr pBuffer, int offset, in Guid guid)
        {
            var guidBytes = guid.ToByteArray();

            for (var idx = 0; idx < guidBytes.Length; idx++)
                Marshal.WriteByte(pBuffer, idx + offset, guidBytes[idx]);
        }


        public static void ZeroMemory(IntPtr pBuffer, int nLength)
        {
            for (var offset = 0; offset < nLength; offset++)
                Marshal.WriteByte(pBuffer, offset, 0);
        }
    }
}
