using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using TokenDump.Interop;

namespace TokenDump.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
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
            int nNameLength = 255;
            int nDomainNameLength = 255;
            var nameBuilder = new StringBuilder(nNameLength);
            var domainNameBuilder = new StringBuilder(nDomainNameLength);
            bool status = NativeMethods.LookupAccountSid(
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
            else
            {
                var hresult = NativeMethods.AppContainerLookupMoniker(pSid, out IntPtr pMoniker);
                name = null;
                sidType = SID_NAME_USE.Unknown;

                if (hresult == Win32Consts.S_OK)
                {
                    status = true;
                    domain = Marshal.PtrToStringUni(pMoniker);
                    NativeMethods.AppContainerFreeMemory(pMoniker);
                }
                else
                {
                    domain = null;
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


        public static bool IsTokenAppContainer(IntPtr hToken, out bool isAppContainer)
        {
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(4);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenIsAppContainer,
                pInfoBuffer,
                4u,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
                isAppContainer = (Marshal.ReadInt32(pInfoBuffer) != 0);
            else
                isAppContainer = false;

            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
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


        public static bool IsTokenRestricted(IntPtr hToken, out bool isRestricted)
        {
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(4);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenIsRestricted,
                pInfoBuffer,
                4u,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
                isRestricted = (Marshal.ReadInt32(pInfoBuffer) != 0);
            else
                isRestricted = false;

            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
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
