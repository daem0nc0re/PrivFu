using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using TokenDump.Interop;

namespace TokenDump.Library
{
    using HRESULT = Int32;
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        public static string ConvertDevicePathToDriveLetter(string devicePath)
        {
            var convertedPath = devicePath;
            var devicePathRegex = new Regex(@"^\\Device\\[^\\]+", RegexOptions.IgnoreCase);
            var driveLetterRegex = new Regex(@"^\\GLOBAL\?\?\\[^:]+:", RegexOptions.IgnoreCase);

            if (!devicePathRegex.IsMatch(devicePath))
                return null;

            if (GetObjectSymbolicLinkTable(out Dictionary<string, string> symlinkTable))
            {
                foreach (var linkMap in symlinkTable)
                {
                    var pattern = string.Format("^{0}", linkMap.Value).Replace("\\", "\\\\");
                    var targetRegex = new Regex(pattern, RegexOptions.IgnoreCase);

                    if (driveLetterRegex.IsMatch(linkMap.Key) && targetRegex.IsMatch(devicePath))
                    {
                        convertedPath = Regex.Replace(devicePath, pattern, linkMap.Key, RegexOptions.IgnoreCase);
                        convertedPath = convertedPath.Replace(@"\GLOBAL??\", string.Empty);
                        break;
                    }
                }
            }

            return convertedPath;
        }


        public static bool ConvertSidToAccountName(
            IntPtr pSid,
            out string account,
            out SID_NAME_USE sidType)
        {
            var status = ConvertSidToAccountName(pSid, out string name, out string domain, out sidType);
            account = null;

            if (status)
            {
                if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(domain))
                    account = string.Format(@"{0}\{1}", domain, name);
                else if (!string.IsNullOrEmpty(domain))
                    account = domain;
                else if (!string.IsNullOrEmpty(name))
                    account = name;
            }

            return status;
        }


        public static bool ConvertSidToAccountName(
            IntPtr pSid,
            out string name,
            out string domain,
            out SID_NAME_USE sidType)
        {
            var status = false;
            var subAuthority = Marshal.ReadInt32(pSid, 8);
            name = null;
            domain = null;

            if ((Marshal.ReadInt64(pSid) == 0x0F000000_00000201L) &&
                (Marshal.ReadInt64(pSid, 8) == 0x00001000_00000003L))
            {
                domain = "APPLICATION PACKAGE AUTHORITY";
                name = "Internet Explorer";
                sidType = SID_NAME_USE.WellKnownGroup;
            }
            else if ((Marshal.ReadInt64(pSid) == 0x0F000000_00000801L) &&
                ((subAuthority == 0x00000002) || (subAuthority == 0x00000003)))
            {
                HRESULT hresult;

                if (subAuthority == 3)
                {
                    domain = "PACKAGE CAPABILITY";
                    Marshal.WriteInt32(pSid, 8, 2);
                }

                hresult = NativeMethods.AppContainerLookupMoniker(pSid, out IntPtr pMoniker);
                sidType = SID_NAME_USE.Unknown;

                if (hresult == Win32Consts.S_OK)
                {
                    status = true;
                    name = Marshal.PtrToStringUni(pMoniker);
                    NativeMethods.AppContainerFreeMemory(pMoniker);
                }
            }
            else
            {
                int nNameLength = 255;
                int nDomainNameLength = 255;
                var nameBuilder = new StringBuilder(nNameLength);
                var domainNameBuilder = new StringBuilder(nDomainNameLength);
                status = NativeMethods.LookupAccountSid(
                    null,
                    pSid,
                    nameBuilder,
                    ref nNameLength,
                    domainNameBuilder,
                    ref nDomainNameLength,
                    out sidType);

                if (status)
                {
                    name = nameBuilder.ToString();
                    domain = domainNameBuilder.ToString();
                }
            }

            return status;
        }


        public static bool ConvertStringSidToAccountName(
            string stringSid,
            out string account,
            out SID_NAME_USE sidType)
        {
            var status = ConvertStringSidToAccountName(
                stringSid,
                out string name,
                out string domain,
                out sidType);
            account = null;

            if (status)
            {
                if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(domain))
                    account = string.Format(@"{0}\{1}", domain, name);
                else if (!string.IsNullOrEmpty(domain))
                    account = domain;
                else if (!string.IsNullOrEmpty(name))
                    account = name;
            }

            return status;
        }


        public static bool ConvertStringSidToAccountName(
            string stringSid,
            out string name,
            out string domain,
            out SID_NAME_USE sidType)
        {
            bool status = NativeMethods.ConvertStringSidToSid(stringSid, out IntPtr pSid);

            if (status)
            {
                status = ConvertSidToAccountName(pSid, out name, out domain, out sidType);
                NativeMethods.LocalFree(pSid);
            }
            else
            {
                name = null;
                domain = null;
                sidType= SID_NAME_USE.Unknown;
            }

            return status;
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


        public static bool EnumerateSubKeys(ref string rootKey, out List<string> subKeys)
        {
            var status = false;
            var objectAttributes = new OBJECT_ATTRIBUTES(
                rootKey,
                OBJECT_ATTRIBUTES_FLAGS.OBJ_CASE_INSENSITIVE);
            NTSTATUS ntstatus = NativeMethods.NtOpenKey(
                out IntPtr hKey,
                ACCESS_MASK.KEY_READ,
                in objectAttributes);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                status = EnumerateSubKeys(hKey, out rootKey, out subKeys);
                NativeMethods.NtClose(hKey);
            }
            else
            {
                subKeys = new List<string>();
            }

            return status;
        }


        public static bool EnumerateSubKeys(
            IntPtr hKey,
            out string rootKey,
            out List<string> subKeys)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            IntPtr pNameBuffer;
            var nInfoLength = 0x800u;
            var nSubKeyCount = 0u;
            var status = false;
            subKeys = new List<string>();
            pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            rootKey = null;

            do
            {
                ntstatus = NativeMethods.NtQueryKey(
                    hKey,
                    KEY_INFORMATION_CLASS.KeyNameInformation,
                    pInfoBuffer,
                    nInfoLength,
                    out uint _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    break;
                }
                else
                {
                    var nameInfo = (KEY_NAME_INFORMATION)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(KEY_NAME_INFORMATION));
                    var nameBytes = new byte[(int)nameInfo.NameLength];
                    int nBufferOffset = Marshal.OffsetOf(typeof(KEY_NAME_INFORMATION), "Name").ToInt32();

                    if (Environment.Is64BitProcess)
                        pNameBuffer = new IntPtr(pInfoBuffer.ToInt64() + nBufferOffset);
                    else
                        pNameBuffer = new IntPtr(pInfoBuffer.ToInt32() + nBufferOffset);

                    Marshal.Copy(pNameBuffer, nameBytes, 0, (int)nameBytes.Length);
                    rootKey = Encoding.Unicode.GetString(nameBytes);
                }

                ntstatus = NativeMethods.NtQueryKey(
                    hKey,
                    KEY_INFORMATION_CLASS.KeyFullInformation,
                    pInfoBuffer,
                    nInfoLength,
                    out uint _);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (status)
                {
                    var info = (KEY_FULL_INFORMATION)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(KEY_FULL_INFORMATION));
                    nSubKeyCount = info.SubKeys;
                }
            } while (false);

            if (!string.IsNullOrEmpty(rootKey) && (nSubKeyCount > 0))
            {
                for (var idx = 0u; idx < nSubKeyCount; idx++)
                {
                    ntstatus = NativeMethods.NtEnumerateKey(
                        hKey,
                        idx,
                        KEY_INFORMATION_CLASS.KeyNodeInformation,
                        pInfoBuffer,
                        nInfoLength,
                        out uint _);

                    if (ntstatus == Win32Consts.STATUS_SUCCESS)
                    {
                        var nodeInfo = (KEY_NODE_INFORMATION)Marshal.PtrToStructure(
                            pInfoBuffer,
                            typeof(KEY_NODE_INFORMATION));
                        var nNameLength = nodeInfo.NameLength;
                        var nameBytes = new byte[(int)nNameLength];
                        var nBufferOffset = Marshal.OffsetOf(typeof(KEY_NODE_INFORMATION), "Name").ToInt32();

                        if (Environment.Is64BitProcess)
                            pNameBuffer = new IntPtr(pInfoBuffer.ToInt64() + nBufferOffset);
                        else
                            pNameBuffer = new IntPtr(pInfoBuffer.ToInt32() + nBufferOffset);

                        Marshal.Copy(pNameBuffer, nameBytes, 0, nameBytes.Length);
                        subKeys.Add(Encoding.Unicode.GetString(nameBytes));
                    }
                }
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return status;
        }


        public static bool GetKnownCapabilitySids(out Dictionary<string, string> capabilitySids)
        {
            string rootKey = @"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\CapabilityMappings";
            bool status = EnumerateSubKeys(ref rootKey, out List<string> capabilities);
            capabilitySids = new Dictionary<string, string>();

            if (status)
            {
                foreach (string capName in capabilities)
                {
                    var regPath = string.Format(@"{0}\{1}", rootKey, capName);
                    status = EnumerateSubKeys(ref regPath, out List<string> subKeys);

                    foreach (var entry in subKeys)
                    {
                        if (Guid.TryParse(entry, out Guid capGuid))
                        {
                            byte[] capGuidBytes = capGuid.ToByteArray();
                            var stringSid = new StringBuilder(@"S-1-15-3");

                            for (var idx = 0; idx < 4; idx++)
                            {
                                stringSid.AppendFormat("-{0}", BitConverter.ToUInt32(capGuidBytes, idx * 4));
                            }

                            if (!capabilitySids.ContainsKey(stringSid.ToString()))
                            {
                                capabilitySids.Add(
                                    stringSid.ToString(),
                                    string.Format(@"NAMED CAPABILITIES\{0}", capName));
                            }
                        }
                    }
                }

                for (var idx = 0; idx < Capabilities.KnownCapabilityNames.Length; idx++)
                {
                    var knownName = Capabilities.KnownCapabilityNames[idx];
                    status = NativeMethods.DeriveCapabilitySidsFromName(
                        knownName,
                        out IntPtr pGroupSids,
                        out int nGroupCount,
                        out IntPtr pCapabilitySids,
                        out int nCapabilityCount);

                    for (var num = 0; num < nGroupCount; num++)
                    {
                        var pSid = Marshal.ReadIntPtr(pGroupSids, num * IntPtr.Size);
                        NativeMethods.ConvertSidToStringSid(pSid, out string stringSid);

                        if (!capabilitySids.ContainsKey(stringSid))
                            capabilitySids.Add(stringSid, string.Format(@"CAPABILITY GROUP\{0}", knownName));

                        NativeMethods.LocalFree(pSid);
                    }

                    for (var num = 0; num < nCapabilityCount; num++)
                    {
                        var pSid = Marshal.ReadIntPtr(pCapabilitySids, num * IntPtr.Size);
                        NativeMethods.ConvertSidToStringSid(pSid, out string stringSid);

                        if (!capabilitySids.ContainsKey(stringSid))
                            capabilitySids.Add(stringSid, string.Format(@"NAMED CAPABILITIES\{0}", knownName));

                        NativeMethods.LocalFree(pSid);
                    }
                }
            }

            return status;
        }


        public static bool GetObjectSymbolicLinkTable(out Dictionary<string, string> symlinkTable)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            bool status;
            string rootPath = @"\GLOBAL??";
            var objectFlags = OBJECT_ATTRIBUTES_FLAGS.OBJ_CASE_INSENSITIVE;
            var nInfoLength = 0x800u;
            var objectAttributes = new OBJECT_ATTRIBUTES(rootPath, objectFlags);
            var symLinks = new List<string>();
            symlinkTable = new Dictionary<string, string>();

            ntstatus = NativeMethods.NtOpenDirectoryObject(
                out IntPtr hDirectory,
                ACCESS_MASK.DIRECTORY_QUERY,
                in objectAttributes);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
                return false;

            do
            {
                var context = 0u;
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryDirectoryObject(
                    hDirectory,
                    pInfoBuffer,
                    nInfoLength,
                    BOOLEAN.FALSE,
                    BOOLEAN.TRUE,
                    ref context,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Marshal.FreeHGlobal(pInfoBuffer);
                    nInfoLength *= 2;
                }
            } while (ntstatus == Win32Consts.STATUS_MORE_ENTRIES);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var pUnicodeString = pInfoBuffer;
                var nUnitSIze = Marshal.SizeOf(typeof(OBJECT_DIRECTORY_INFORMATION));

                while (Marshal.ReadIntPtr(pUnicodeString, IntPtr.Size) != IntPtr.Zero)
                {
                    var info = (OBJECT_DIRECTORY_INFORMATION)Marshal.PtrToStructure(
                        pUnicodeString,
                        typeof(OBJECT_DIRECTORY_INFORMATION));

                    if (CompareIgnoreCase(info.TypeName.ToString(), "SymbolicLink"))
                        symLinks.Add(string.Format(@"{0}\{1}", rootPath, info.Name.ToString()));

                    if (Environment.Is64BitProcess)
                        pUnicodeString = new IntPtr(pUnicodeString.ToInt64() + nUnitSIze);
                    else
                        pUnicodeString = new IntPtr(pUnicodeString.ToInt32() + nUnitSIze);
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            NativeMethods.NtClose(hDirectory);
            status = (symLinks.Count > 0);

            foreach (var link in symLinks)
            {
                objectAttributes = new OBJECT_ATTRIBUTES(link, objectFlags);
                ntstatus = NativeMethods.NtOpenSymbolicLinkObject(
                    out IntPtr hSymLink,
                    ACCESS_MASK.SYMBOLIC_LINK_QUERY,
                    in objectAttributes);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                {
                    var referencedPath = new UNICODE_STRING();
                    nInfoLength = 512u;

                    do
                    {
                        pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                        referencedPath.MaximumLength = (ushort)(nInfoLength & 0xFFFF);
                        referencedPath.SetBuffer(pInfoBuffer);
                        ntstatus = NativeMethods.NtQuerySymbolicLinkObject(
                            hSymLink,
                            ref referencedPath,
                            out nInfoLength);

                        if (ntstatus != Win32Consts.STATUS_SUCCESS)
                            Marshal.FreeHGlobal(pInfoBuffer);
                    } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

                    if (ntstatus == Win32Consts.STATUS_SUCCESS)
                    {
                        symlinkTable.Add(link, referencedPath.ToString());
                        Marshal.FreeHGlobal(pInfoBuffer);
                    }
                }

                NativeMethods.NtClose(hSymLink);
            }

            return status;
        }


        public static Dictionary<int, string> GetObjectTypeTable()
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoSize = (uint)Marshal.SizeOf(typeof(OBJECT_TYPES_INFORMATION));
            var table = new Dictionary<int, string>();

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

                    table.Add((int)entry.TypeIndex, entry.TypeName.ToString());

                    if (Environment.Is64BitProcess)
                        pEntry = new IntPtr(pEntry.ToInt64() + nNextOffset);
                    else
                        pEntry = new IntPtr(pEntry.ToInt32() + nNextOffset);
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return table;
        }


        public static string GetProcessCommandLine(IntPtr hProcess)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            string processName = null;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(UNICODE_STRING));

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationProcess(
                    hProcess,
                    PROCESSINFOCLASS.ProcessCommandLineInformation,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_INFO_LENGTH_MISMATCH);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var nameData = (UNICODE_STRING)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(UNICODE_STRING));
                processName = nameData.ToString();
                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return processName;
        }


        public static string GetProcessImageFilePath(IntPtr hProcess)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            string imageFilePath = null;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(UNICODE_STRING));

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationProcess(
                    hProcess,
                    PROCESSINFOCLASS.ProcessImageFileName,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_INFO_LENGTH_MISMATCH);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var nameData = (UNICODE_STRING)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(UNICODE_STRING));
                imageFilePath = nameData.ToString();

                if (string.IsNullOrEmpty(imageFilePath))
                    imageFilePath = null;

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return imageFilePath;
        }


        public static bool GetSystemHandles(
            string typeName,
            out Dictionary<int, List<SYSTEM_HANDLE_TABLE_ENTRY_INFO>> handles)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            int tokenIndex = -1;
            var typeTable = GetObjectTypeTable();
            var nInfoSize = (uint)Marshal.SizeOf(typeof(SYSTEM_HANDLE_INFORMATION));
            handles = new Dictionary<int, List<SYSTEM_HANDLE_TABLE_ENTRY_INFO>>();

            if (typeTable.Count == 0)
            {
                return false;
            }
            else
            {
                foreach (var entry in typeTable)
                {
                    if (CompareIgnoreCase(entry.Value, typeName))
                    {
                        tokenIndex = (int)entry.Key;
                        break;
                    }
                }

                if (tokenIndex == -1)
                    return false;
            }

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

                    if (handles.ContainsKey(entry.UniqueProcessId) && ((int)entry.ObjectTypeIndex == tokenIndex))
                    {
                        handles[entry.UniqueProcessId].Add(entry);
                    }
                    else if ((int)entry.ObjectTypeIndex == tokenIndex)
                    {
                        handles.Add(
                            entry.UniqueProcessId,
                            new List<SYSTEM_HANDLE_TABLE_ENTRY_INFO> { entry });
                    }
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
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


        public static bool GetThreadBasicInformation(
            IntPtr hThread,
            out THREAD_BASIC_INFORMATION tbi)
        {
            var nInfoLength = (uint)Marshal.SizeOf(typeof(THREAD_BASIC_INFORMATION));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationThread(
                hThread,
                THREADINFOCLASS.ThreadBasicInformation,
                pInfoBuffer,
                nInfoLength,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                tbi = (THREAD_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(THREAD_BASIC_INFORMATION));
            }
            else
            {
                tbi = new THREAD_BASIC_INFORMATION();
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetTokenAccessFlags(IntPtr hToken, out TokenFlags flags)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_ACCESS_INFORMATION));
            flags = 0;

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenAccessInformation,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var info = (TOKEN_ACCESS_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(TOKEN_ACCESS_INFORMATION));
                flags = info.Flags;

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetTokenAppContainerNumber(IntPtr hToken, out uint nAppContainers)
        {
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(4);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenAppContainerNumber,
                pInfoBuffer,
                4u,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
                nAppContainers = (uint)Marshal.ReadInt32(pInfoBuffer);
            else
                nAppContainers = uint.MaxValue;

            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetTokenAppContainerSid(IntPtr hToken, out string stringSid, out string accountName)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var status = false;
            var nInfoLength = (uint)(Marshal.SizeOf(typeof(TOKEN_APPCONTAINER_INFORMATION)) + 0x100);
            stringSid = null;
            accountName = null;

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenAppContainerSid,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var info = (TOKEN_APPCONTAINER_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(TOKEN_APPCONTAINER_INFORMATION));
                IntPtr pSid = info.TokenAppContainer;
                status = NativeMethods.ConvertSidToStringSid(pSid, out stringSid);

                if (status)
                    ConvertSidToAccountName(pSid, out accountName, out SID_NAME_USE _);
                else
                    stringSid = null;

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return status;
        }


        public static Dictionary<string, SE_GROUP_ATTRIBUTES> GetTokenCapabilities(IntPtr hToken)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_GROUPS));
            var capabilities = new Dictionary<string, SE_GROUP_ATTRIBUTES>();

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenCapabilities,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                IntPtr pEntry;
                int nOffset = Marshal.OffsetOf(typeof(TOKEN_GROUPS), "Groups").ToInt32();
                int nUnitSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
                int nEntryCount = Marshal.ReadInt32(pInfoBuffer);

                for (var idx = 0; idx < nEntryCount; idx++)
                {
                    if (Environment.Is64BitProcess)
                        pEntry = new IntPtr(pInfoBuffer.ToInt64() + nOffset + (idx * nUnitSize));
                    else
                        pEntry = new IntPtr(pInfoBuffer.ToInt32() + nOffset + (idx * nUnitSize));

                    var entry = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                        pEntry,
                        typeof(SID_AND_ATTRIBUTES));
                    NativeMethods.ConvertSidToStringSid(entry.Sid, out string stringSid);
                    capabilities.Add(stringSid, (SE_GROUP_ATTRIBUTES)entry.Attributes);
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return capabilities;
        }


        public static bool GetTokenDefaultDacl(
            IntPtr hToken,
            out List<AceInformation> info)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_DEFAULT_DACL));
            info = new List<AceInformation>();

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenDefaultDacl,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                IntPtr pAce;
                IntPtr pSid;
                var pAcl = Marshal.ReadIntPtr(pInfoBuffer);
                var acl = (ACL)Marshal.PtrToStructure(pAcl, typeof(ACL));

                if (Environment.Is64BitProcess)
                    pAce = new IntPtr(pAcl.ToInt64() + Marshal.SizeOf(typeof(ACL)));
                else
                    pAce = new IntPtr(pAcl.ToInt32() + Marshal.SizeOf(typeof(ACL)));

                for (var idx = 0; idx < acl.AceCount; idx++)
                {
                    uint accessMask;
                    int nSidOffset;
                    var entry = new AceInformation();
                    var aceHeader = (ACE_HEADER)Marshal.PtrToStructure(pAce, typeof(ACE_HEADER));

                    if (aceHeader.AceType == ACE_TYPE.AccessAllowed)
                    {
                        var ace = (ACCESS_ALLOWED_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_ALLOWED_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(ACCESS_ALLOWED_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.AccessAllowedCallback)
                    {
                        var ace = (ACCESS_ALLOWED_CALLBACK_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_ALLOWED_CALLBACK_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(ACCESS_ALLOWED_CALLBACK_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.AccessAllowedCallbackObject)
                    {
                        var ace = (ACCESS_ALLOWED_CALLBACK_OBJECT_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.AccessAllowedObject)
                    {
                        var ace = (ACCESS_ALLOWED_OBJECT_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_ALLOWED_OBJECT_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(ACCESS_ALLOWED_OBJECT_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.AccessDenied)
                    {
                        var ace = (ACCESS_DENIED_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_DENIED_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(ACCESS_DENIED_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.AccessDeniedCallback)
                    {
                        var ace = (ACCESS_DENIED_CALLBACK_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_DENIED_CALLBACK_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(ACCESS_DENIED_CALLBACK_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.AccessDeniedCallbackObject)
                    {
                        var ace = (ACCESS_DENIED_CALLBACK_OBJECT_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_DENIED_CALLBACK_OBJECT_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(ACCESS_DENIED_CALLBACK_OBJECT_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.AccessDeniedObject)
                    {
                        var ace = (ACCESS_DENIED_OBJECT_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_DENIED_OBJECT_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(ACCESS_DENIED_OBJECT_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.SystemAlarm)
                    {
                        var ace = (SYSTEM_ALARM_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_ALARM_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_ALARM_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.SystemAlarmCallback)
                    {
                        var ace = (SYSTEM_ALARM_CALLBACK_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_ALARM_CALLBACK_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_ALARM_CALLBACK_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.SystemAlarmCallbackObject)
                    {
                        var ace = (SYSTEM_ALARM_CALLBACK_OBJECT_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_ALARM_CALLBACK_OBJECT_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_ALARM_CALLBACK_OBJECT_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.SystemAlarmObject)
                    {
                        var ace = (SYSTEM_ALARM_OBJECT_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_ALARM_OBJECT_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_ALARM_OBJECT_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.SystemAudit)
                    {
                        var ace = (SYSTEM_AUDIT_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_AUDIT_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_AUDIT_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.SystemAuditCallback)
                    {
                        var ace = (SYSTEM_AUDIT_CALLBACK_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_AUDIT_CALLBACK_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_AUDIT_CALLBACK_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.SystemAuditCallbackObject)
                    {
                        var ace = (SYSTEM_AUDIT_CALLBACK_OBJECT_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.SystemAuditCallback)
                    {
                        var ace = (SYSTEM_AUDIT_OBJECT_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_AUDIT_OBJECT_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_AUDIT_OBJECT_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.SystemMandatoryLabel)
                    {
                        var ace = (SYSTEM_MANDATORY_LABEL_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_MANDATORY_LABEL_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_MANDATORY_LABEL_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.SystemMandatoryLabel)
                    {
                        var ace = (SYSTEM_MANDATORY_LABEL_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_MANDATORY_LABEL_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_MANDATORY_LABEL_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.SystemResourceAttribute)
                    {
                        var ace = (SYSTEM_RESOURCE_ATTRIBUTE_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_RESOURCE_ATTRIBUTE_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_RESOURCE_ATTRIBUTE_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.SystemScopedPolicyId)
                    {
                        var ace = (SYSTEM_SCOPED_POLICY_ID_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_SCOPED_POLICY_ID_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_SCOPED_POLICY_ID_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.SystemProcessTrustLabel)
                    {
                        var ace = (SYSTEM_PROCESS_TRUST_LABEL_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_PROCESS_TRUST_LABEL_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_PROCESS_TRUST_LABEL_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else if (aceHeader.AceType == ACE_TYPE.SystemAccessFilter)
                    {
                        var ace = (SYSTEM_ACCESS_FILTER_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_ACCESS_FILTER_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_ACCESS_FILTER_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }
                    else
                    {
                        var ace = (ACCESS_ALLOWED_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_ALLOWED_ACE));
                        nSidOffset = Marshal.OffsetOf(typeof(ACCESS_ALLOWED_ACE), "SidStart").ToInt32();
                        accessMask = (uint)ace.Mask;
                    }

                    if (Environment.Is64BitProcess)
                        pSid = new IntPtr(pAce.ToInt64() + nSidOffset);
                    else
                        pSid = new IntPtr(pAce.ToInt32() + nSidOffset);

                    ConvertSidToAccountName(pSid, out string account, out SID_NAME_USE _);
                    NativeMethods.ConvertSidToStringSid(pSid, out string stringSid);
                    entry.AccountName = string.IsNullOrEmpty(account) ? stringSid : account;
                    entry.AccountSid = stringSid;
                    entry.AccessMask = (ACCESS_MASK)accessMask;
                    entry.Flags = aceHeader.AceFlags;
                    entry.Type = aceHeader.AceType;
                    info.Add(entry);

                    if (Environment.Is64BitProcess)
                        pAce = new IntPtr(pAce.ToInt64() + aceHeader.AceSize);
                    else
                        pAce = new IntPtr(pAce.ToInt32() + aceHeader.AceSize);
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetTokenElevationType(
            IntPtr hToken,
            out TOKEN_ELEVATION_TYPE elevationType)
        {
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(4);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenElevationType,
                pInfoBuffer,
                4u,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
                elevationType = (TOKEN_ELEVATION_TYPE)Marshal.ReadInt32(pInfoBuffer);
            else
                elevationType = 0;

            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetTokenGroups(
            IntPtr hToken,
            out Dictionary<string, SE_GROUP_ATTRIBUTES> groups)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_GROUPS));
            groups = new Dictionary<string, SE_GROUP_ATTRIBUTES>();

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
                IntPtr pEntry;
                var nGroupCount = Marshal.ReadInt32(pInfoBuffer);
                var nGroupsOffset = Marshal.OffsetOf(typeof(TOKEN_GROUPS), "Groups").ToInt32();
                var nUnitSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));

                for (var idx = 0; idx < nGroupCount; idx++)
                {
                    if (Environment.Is64BitProcess)
                        pEntry = new IntPtr(pInfoBuffer.ToInt64() + nGroupsOffset + (nUnitSize * idx));
                    else
                        pEntry = new IntPtr(pInfoBuffer.ToInt32() + nGroupsOffset + (nUnitSize * idx));

                    var entry = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                        pEntry,
                        typeof(SID_AND_ATTRIBUTES));

                    NativeMethods.ConvertSidToStringSid(entry.Sid, out string stringSid);
                    groups.Add(stringSid, (SE_GROUP_ATTRIBUTES)entry.Attributes);
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return true;
        }


        public static string GetTokenIntegrityLevel(IntPtr hToken)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            string level = null;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL));

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var info = (TOKEN_MANDATORY_LABEL)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(TOKEN_MANDATORY_LABEL));
                var status = ConvertSidToAccountName(
                    info.Label.Sid,
                    out string name,
                    out string _,
                    out SID_NAME_USE _);
                Marshal.FreeHGlobal(pInfoBuffer);

                if (status)
                {
                    try
                    {
                        level = name.Split(' ')[0];
                    }
                    catch
                    {
                        level = null;
                    }
                }
            }

            return level;
        }


        public static bool GetTokenLinkedToken(
            IntPtr hToken,
            out IntPtr hLinkedToken,
            out bool hasLinkedToken)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            var status = false;
            hLinkedToken = IntPtr.Zero;
            hasLinkedToken = false;
            Marshal.WriteIntPtr(pInfoBuffer, IntPtr.Zero);
            
            ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenLinkedToken,
                pInfoBuffer,
                (uint)IntPtr.Size,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                hLinkedToken = Marshal.ReadIntPtr(pInfoBuffer);
                hasLinkedToken = true;
                status = true;
            }
            else if (ntstatus == Win32Consts.STATUS_NO_SUCH_LOGON_SESSION)
            {
                status = true;
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return status;
        }


        public static bool GetTokenLogonSid(
            IntPtr hToken,
            out Dictionary<string, SE_GROUP_ATTRIBUTES> logonSids)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_GROUPS));
            logonSids = new Dictionary<string, SE_GROUP_ATTRIBUTES>();

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
                IntPtr pEntry;
                var nGroupCount = Marshal.ReadInt32(pInfoBuffer);
                var nGroupsOffset = Marshal.OffsetOf(typeof(TOKEN_GROUPS), "Groups").ToInt32();
                var nUnitSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));

                for (var idx = 0; idx < nGroupCount; idx++)
                {
                    if (Environment.Is64BitProcess)
                        pEntry = new IntPtr(pInfoBuffer.ToInt64() + nGroupsOffset + (nUnitSize * idx));
                    else
                        pEntry = new IntPtr(pInfoBuffer.ToInt32() + nGroupsOffset + (nUnitSize * idx));

                    var entry = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                        pEntry,
                        typeof(SID_AND_ATTRIBUTES));

                    NativeMethods.ConvertSidToStringSid(entry.Sid, out string stringSid);
                    logonSids.Add(stringSid, (SE_GROUP_ATTRIBUTES)entry.Attributes);
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetTokenMandatoryPolicy(IntPtr hToken, out TOKEN_MANDATORY_POLICY_FLAGS policy)
        {
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_MANDATORY_POLICY));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenMandatoryPolicy,
                pInfoBuffer,
                nInfoLength,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
                policy = (TOKEN_MANDATORY_POLICY_FLAGS)Marshal.ReadInt32(pInfoBuffer);
            else
                policy = TOKEN_MANDATORY_POLICY_FLAGS.None;

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetTokenOrigin(IntPtr hToken, out TOKEN_ORIGIN tokenOrigin)
        {
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_ORIGIN));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenOrigin,
                pInfoBuffer,
                nInfoLength,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                tokenOrigin = (TOKEN_ORIGIN)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(TOKEN_ORIGIN));
            }
            else
            {
                tokenOrigin = new TOKEN_ORIGIN();
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static string GetTokenOwnerSid(IntPtr hToken)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            string stringSid = null;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_OWNER));

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenOwner,
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


        public static string GetTokenPrimaryGroupSid(IntPtr hToken)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            string stringSid = null;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_PRIMARY_GROUP));

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenPrimaryGroup,
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


        public static bool GetTokenRestrictedSids(
            IntPtr hToken,
            out Dictionary<string, SE_GROUP_ATTRIBUTES> restrictedGroups)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_GROUPS));
            restrictedGroups = new Dictionary<string, SE_GROUP_ATTRIBUTES>();

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenRestrictedSids,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                IntPtr pEntry;
                var nEntryCount = Marshal.ReadInt32(pInfoBuffer);
                var nUnitSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));

                for (var idx = 0; idx < nEntryCount; idx++)
                {
                    if (Environment.Is64BitProcess)
                        pEntry = new IntPtr(pInfoBuffer.ToInt64() + 8 + (idx * nUnitSize));
                    else
                        pEntry = new IntPtr(pInfoBuffer.ToInt32() + 4 + (idx * nUnitSize));

                    var entry = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                        pEntry,
                        typeof(SID_AND_ATTRIBUTES));

                    NativeMethods.ConvertSidToStringSid(entry.Sid, out string stringSid);
                    restrictedGroups.Add(stringSid, (SE_GROUP_ATTRIBUTES)entry.Attributes);
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        // Returned buffer must be free with Marshal.FreeHGlobal
        public static IntPtr GetTokenSecurityAttributes(IntPtr hToken)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_SECURITY_ATTRIBUTES_INFORMATION));

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenSecurityAttributes,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Marshal.FreeHGlobal(pInfoBuffer);
                    pInfoBuffer = IntPtr.Zero;
                }
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            return pInfoBuffer;
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


        public static bool GetTokenSource(IntPtr hToken, out TOKEN_SOURCE tokenSource)
        {
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_SOURCE));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenSource,
                pInfoBuffer,
                nInfoLength,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                tokenSource = (TOKEN_SOURCE)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(TOKEN_SOURCE));
            }
            else
            {
                ZeroMemory(pInfoBuffer, (int)nInfoLength);
                tokenSource = (TOKEN_SOURCE)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(TOKEN_SOURCE));
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetTokenStatistics(IntPtr hToken, out TOKEN_STATISTICS tokenStatistics)
        {
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_STATISTICS));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenStatistics,
                pInfoBuffer,
                nInfoLength,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                tokenStatistics = (TOKEN_STATISTICS)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(TOKEN_STATISTICS));
            }
            else
            {
                tokenStatistics = new TOKEN_STATISTICS();
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetTokenTrustLevel(
            IntPtr hToken,
            out string trustLabel,
            out string stringSid)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_PROCESS_TRUST_LEVEL));
            trustLabel = null;
            stringSid = null;

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenProcessTrustLevel,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var pSid = Marshal.ReadIntPtr(pInfoBuffer);

                if (pSid != IntPtr.Zero)
                {
                    if (Marshal.ReadInt64(pSid) == 0x13000000_00000201L)
                    {
                        string protectionLevel = null;
                        string signerLevel = null;
                        var protectionRid = Marshal.ReadInt32(pSid, 0x8);
                        var signerRid = Marshal.ReadInt32(pSid, 0xC);

                        if (protectionRid == 512)
                            protectionLevel = "ProtectedLight";
                        else if (protectionRid == 1024)
                            protectionLevel = "Protected";

                        if (signerRid == 0x400)
                            signerLevel = "Authenticode";
                        else if (signerRid == 0x600)
                            signerLevel = "AntiMalware";
                        else if (signerRid == 0x800)
                            signerLevel = "App";
                        else if (signerRid == 0x1000)
                            signerLevel = "Windows";
                        else if (signerRid == 0x2000)
                            signerLevel = "WinTcb";

                        if (!string.IsNullOrEmpty(protectionLevel) && !string.IsNullOrEmpty(signerLevel))
                        {
                            trustLabel = string.Format(@"TRUST LEVEL\{0}-{1}", protectionLevel, signerLevel);
                            NativeMethods.ConvertSidToStringSid(pSid, out stringSid);
                        }
                    }
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
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


        public static bool IsTokenAppContainer(IntPtr hToken)
        {
            var isAppContainer = false;
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(4);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenIsAppContainer,
                pInfoBuffer,
                4u,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
                isAppContainer = (Marshal.ReadInt32(pInfoBuffer) != 0);

            Marshal.FreeHGlobal(pInfoBuffer);

            return isAppContainer;
        }


        public static bool IsTokenElevated(IntPtr hToken, out bool isElevated)
        {
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(4);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenElevation,
                pInfoBuffer,
                4u,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
                isElevated = (Marshal.ReadInt32(pInfoBuffer) != 0);
            else
                isElevated = false;

            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool IsTokenRestricted(IntPtr hToken)
        {
            var isRestricted = false;
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(4);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenIsRestricted,
                pInfoBuffer,
                4u,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
                isRestricted = (Marshal.ReadInt32(pInfoBuffer) != 0);

            Marshal.FreeHGlobal(pInfoBuffer);

            return isRestricted;
        }


        public static bool OpenRemoteThread(
            int pid,
            int tid,
            ACCESS_MASK processAccess,
            ACCESS_MASK threadAccess,
            out IntPtr hProcess,
            out IntPtr hThread)
        {
            bool status = GetSystemHandles(
                "Thread",
                out Dictionary<int, List<SYSTEM_HANDLE_TABLE_ENTRY_INFO>> threadHandles);
            processAccess |= ACCESS_MASK.PROCESS_DUP_HANDLE;
            hProcess = IntPtr.Zero;
            hThread = IntPtr.Zero;

            if (!status || !threadHandles.ContainsKey(pid))
                return false;

            hProcess = NativeMethods.OpenProcess(
                processAccess,
                false,
                pid);

            if (hProcess != IntPtr.Zero)
            {
                foreach (var thread in threadHandles[pid])
                {
                    var ntstatus = NativeMethods.NtDuplicateObject(
                        hProcess,
                        new IntPtr(thread.HandleValue),
                        new IntPtr(-1),
                        out IntPtr hDupObject,
                        threadAccess,
                        0,
                        0);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                        continue;

                    status = GetThreadBasicInformation(
                        hDupObject,
                        out THREAD_BASIC_INFORMATION tbi);

                    if (status && (tbi.ClientId.UniqueProcess.ToInt32() == pid))
                    {
                        if (tbi.ClientId.UniqueThread.ToInt32() == tid)
                        {
                            hThread = hDupObject;
                            break;
                        }
                    }

                    if (hThread == IntPtr.Zero)
                        NativeMethods.NtClose(hDupObject);
                }

                if (hThread == IntPtr.Zero)
                {
                    NativeMethods.NtClose(hProcess);
                    hProcess = IntPtr.Zero;
                }
            }

            return ((hProcess != IntPtr.Zero) && (hThread != IntPtr.Zero));
        }


        public static void ZeroMemory(IntPtr pBuffer, int nRange)
        {
            for (var offset = 0; offset < nRange; offset++)
                Marshal.WriteByte(pBuffer, offset, 0);
        }
    }
}
