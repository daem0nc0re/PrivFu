using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using S4uDelegator.Interop;

namespace S4uDelegator.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        public static string ConvertAccountNameToStringSid(
            ref string accountName,
            out SID_NAME_USE sidType)
        {
            bool status;
            int error;
            IntPtr pSid;
            string stringSid = null;
            int nSidLength = 256;
            int nDomainLength = 256;
            var domainBuilder = new StringBuilder(nDomainLength);
            sidType = SID_NAME_USE.Unknown;

            if (string.IsNullOrEmpty(accountName))
                return null;

            do
            {
                pSid = Marshal.AllocHGlobal(nSidLength);
                status = NativeMethods.LookupAccountName(
                    null,
                    accountName,
                    pSid,
                    ref nSidLength,
                    domainBuilder,
                    ref nDomainLength,
                    out sidType);
                error = Marshal.GetLastWin32Error();

                if (!status)
                {
                    Marshal.FreeHGlobal(pSid);
                    domainBuilder.Capacity = nDomainLength;
                }
            } while (!status && (error == Win32Consts.ERROR_INSUFFICIENT_BUFFER));

            if (status)
            {
                ConvertSidToAccountName(
                    pSid,
                    out string name,
                    out string domain,
                    out sidType);
                NativeMethods.ConvertSidToStringSid(pSid, out stringSid);

                if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(domain))
                    accountName = string.Format(@"{0}\{1}", domain, name);
                else if (!string.IsNullOrEmpty(name))
                    accountName = name;
                else if (!string.IsNullOrEmpty(domain))
                    accountName = domain;

                Marshal.FreeHGlobal(pSid);
                domainBuilder.Clear();
            }

            return stringSid;
        }


        public static string ConvertStringSidToAccountName(
            ref string stringSid,
            out SID_NAME_USE sidType)
        {
            string accountName = null;
            stringSid = stringSid.ToUpper();
            sidType = SID_NAME_USE.Unknown;

            if (NativeMethods.ConvertStringSidToSid(stringSid, out IntPtr pSid))
            {
                ConvertSidToAccountName(
                    pSid,
                    out string name,
                    out string domain,
                    out sidType);
                NativeMethods.LocalFree(pSid);

                if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(domain))
                    accountName = string.Format(@"{0}\{1}", domain, name);
                else if (!string.IsNullOrEmpty(name))
                    accountName = name;
                else if (!string.IsNullOrEmpty(domain))
                    accountName = domain;
            }

            return accountName;
        }


        public static bool ConvertSidToAccountName(
            IntPtr pSid,
            out string name,
            out string domain,
            out SID_NAME_USE sidType)
        {
            int nNameLength = 255;
            int nDomainLength = 255;
            var nameBuilder = new StringBuilder(nNameLength);
            var domainBuilder = new StringBuilder(nDomainLength);
            bool status = NativeMethods.LookupAccountSid(
                null,
                pSid,
                nameBuilder,
                ref nNameLength,
                domainBuilder,
                ref nDomainLength,
                out sidType);

            if (status)
            {
                name = (nNameLength == 0) ? null : nameBuilder.ToString();
                domain = (nDomainLength == 0) ? null : domainBuilder.ToString();
            }
            else
            {
                name = null;
                domain = null;
                sidType = SID_NAME_USE.Unknown;
            }

            return status;
        }


        public static string GetCurrentDomainName()
        {
            bool status;
            int nNameLength = 255;
            string domainName = Environment.UserDomainName;
            var nameBuilder = new StringBuilder(nNameLength);

            do
            {
                status = NativeMethods.GetComputerNameEx(
                    COMPUTER_NAME_FORMAT.DnsDomain,
                    nameBuilder,
                    ref nNameLength);

                if (!status)
                {
                    nameBuilder.Clear();
                    nameBuilder.Capacity = nNameLength;
                }
            } while (Marshal.GetLastWin32Error() == Win32Consts.ERROR_MORE_DATA);

            if (status && (nNameLength > 0))
                domainName = nameBuilder.ToString();

            return domainName;
        }


        public static bool GetLocalGroups(out List<string> localGroups)
        {
            bool status;
            int error;
            int nEntrySize = Marshal.SizeOf(typeof(GROUP_INFO_0));
            int nMaximumLength = 0x4000;
            localGroups = new List<string>();

            error = NativeMethods.NetGroupEnum(
                null,
                0,
                out IntPtr pDataBuffer,
                nMaximumLength,
                out int nEntries,
                out int _,
                IntPtr.Zero);
            status = (error == Win32Consts.ERROR_SUCCESS);

            if (status)
            {
                IntPtr pEntry;

                for (var idx = 0; idx < nEntries; idx++)
                {
                    if (Environment.Is64BitProcess)
                        pEntry = new IntPtr(pDataBuffer.ToInt64() + (idx * nEntrySize));
                    else
                        pEntry = new IntPtr(pDataBuffer.ToInt32() + (idx * nEntrySize));

                    var entry = (GROUP_INFO_0)Marshal.PtrToStructure(pEntry, typeof(GROUP_INFO_0));
                    localGroups.Add(entry.grpi0_name);
                }

                NativeMethods.NetApiBufferFree(pDataBuffer);
            }

            return status;
        }


        public static bool GetLocalUsers(out Dictionary<string, bool> localUsers)
        {
            bool status;
            int error;
            int nEntrySize = Marshal.SizeOf(typeof(USER_INFO_1));
            int nMaximumLength = 0x4000;
            localUsers = new Dictionary<string, bool>();

            error = NativeMethods.NetUserEnum(
                null,
                1,
                USER_INFO_FILTER.NORMAL_ACCOUNT,
                out IntPtr pDataBuffer,
                nMaximumLength,
                out int nEntries,
                out int _,
                IntPtr.Zero);
            status = (error == Win32Consts.ERROR_SUCCESS);

            if (status)
            {
                IntPtr pEntry;
                bool available;

                for (var idx = 0; idx < nEntries; idx++)
                {
                    if (Environment.Is64BitProcess)
                        pEntry = new IntPtr(pDataBuffer.ToInt64() + (idx * nEntrySize));
                    else
                        pEntry = new IntPtr(pDataBuffer.ToInt32() + (idx * nEntrySize));

                    var entry = (USER_INFO_1)Marshal.PtrToStructure(pEntry, typeof(USER_INFO_1));
                    available = !((entry.usri1_flags & (USER_FLAGS.UF_ACCOUNTDISABLE | USER_FLAGS.UF_LOCKOUT)) != 0);
                    localUsers.Add(entry.usri1_name, available);
                }

                NativeMethods.NetApiBufferFree(pDataBuffer);
            }

            return status;
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


        public static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            int nReturnedLength;
            int nSizeMesssage = 256;
            var message = new StringBuilder(nSizeMesssage);
            var dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            var pNtdll = IntPtr.Zero;

            if (isNtStatus)
            {
                foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
                {
                    if (CompareIgnoreCase(Path.GetFileName(module.FileName), "ntdll.dll"))
                    {
                        pNtdll = module.BaseAddress;
                        dwFlags |= FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE;
                        break;
                    }
                }
            }

            nReturnedLength = NativeMethods.FormatMessage(
                dwFlags,
                pNtdll,
                code,
                0,
                message,
                nSizeMesssage,
                IntPtr.Zero);

            if (nReturnedLength == 0)
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            else
                return string.Format("[ERROR] Code 0x{0} : {1}", code.ToString("X8"), message.ToString().Trim());
        }


        public static bool IsDomainMachine()
        {
            return !CompareIgnoreCase(GetCurrentDomainName(), Environment.MachineName);
        }


        public static void ZeroMemory(IntPtr pBuffer, int nSize)
        {
            for (var offset = 0; offset < nSize; offset++)
                Marshal.WriteByte(pBuffer, offset, 0);
        }
    }
}
