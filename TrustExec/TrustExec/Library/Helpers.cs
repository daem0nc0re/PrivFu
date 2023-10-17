using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using TrustExec.Interop;

namespace TrustExec.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static NTSTATUS AddSidMapping(string domain, string username, IntPtr pSid)
        {
            NTSTATUS ntstatus;
            var input = new LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT { Sid = pSid };
            IntPtr pInputBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(input));

            if (!string.IsNullOrEmpty(domain))
                input.DomainName = new UNICODE_STRING(domain);

            if (!string.IsNullOrEmpty(username))
                input.AccountName = new UNICODE_STRING(username);

            Marshal.StructureToPtr(input, pInputBuffer, false);
            ntstatus = NativeMethods.LsaManageSidNameMapping(
                LSA_SID_NAME_MAPPING_OPERATION_TYPE.Add,
                pInputBuffer,
                out IntPtr pOutputBuffer);
            Marshal.FreeHGlobal(pInputBuffer);

            if (pOutputBuffer != IntPtr.Zero)
                NativeMethods.LsaFreeMemory(pOutputBuffer);

            return ntstatus;
        }


        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        public static bool ConvertAccountNameToSidString(
            ref string accountName,
            ref string domainName,
            out string sidString,
            out SID_NAME_USE peUse)
        {
            int error;
            bool status;
            string nameToLookup;
            int nSidSize = 0;
            int nReferencedDomainNameLength = 255;
            var referencedDomainName = new StringBuilder();
            var pSid = IntPtr.Zero;
            sidString = null;
            peUse = SID_NAME_USE.Unknown;

            if (!string.IsNullOrEmpty(domainName) && domainName.Trim() == ".")
                domainName = Environment.MachineName;
            else if (!string.IsNullOrEmpty(accountName) && accountName.Trim() == ".")
                accountName = Environment.MachineName;

            if (!string.IsNullOrEmpty(accountName) && !string.IsNullOrEmpty(domainName))
                nameToLookup = string.Format(@"{0}\{1}", domainName, accountName);
            else if (!string.IsNullOrEmpty(accountName))
                nameToLookup = accountName;
            else if (!string.IsNullOrEmpty(domainName))
                nameToLookup = domainName;
            else
                return false;

            do
            {
                referencedDomainName.Capacity = nReferencedDomainNameLength;
                status = NativeMethods.LookupAccountName(
                    null,
                    nameToLookup,
                    pSid,
                    ref nSidSize,
                    referencedDomainName,
                    ref nReferencedDomainNameLength,
                    out peUse);
                error = Marshal.GetLastWin32Error();

                if (!status)
                {
                    if (pSid != IntPtr.Zero)
                        Marshal.FreeHGlobal(pSid);

                    if (error == Win32Consts.ERROR_INSUFFICIENT_BUFFER)
                        pSid = Marshal.AllocHGlobal(nSidSize);

                    referencedDomainName.Clear();
                    peUse = SID_NAME_USE.Unknown;
                }
            } while (error == Win32Consts.ERROR_INSUFFICIENT_BUFFER);

            if (status)
            {
                ConvertSidToAccountName(pSid, out accountName, out domainName, out peUse);
                NativeMethods.ConvertSidToStringSid(pSid, out sidString);
                Marshal.FreeHGlobal(pSid);
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


        public static string[] ParseGroupSids(string extraSidsString)
        {
            var result = new List<string>();
            var sidArray = extraSidsString.Split(',');
            var regexSid = new Regex(
                @"^S-1(-\d+)+$",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);
            string accountName;
            string sid;

            Console.WriteLine("[>] Parsing group SID(s).");

            for (var idx = 0; idx < sidArray.Length; idx++)
            {
                sid = sidArray[idx].Trim();

                if (!regexSid.IsMatch(sid))
                {
                    Console.WriteLine("[!] {0} is invalid format. Ignored.", sid);
                    continue;
                }

                if (ConvertSidStringToAccountName(
                    ref sid,
                    out string account,
                    out string domain,
                    out SID_NAME_USE peUse))
                {
                    if (!string.IsNullOrEmpty(account) && !string.IsNullOrEmpty(domain))
                        accountName = string.Format(@"{0}\{1}", domain, account);
                    else if (!string.IsNullOrEmpty(account))
                        accountName = account;
                    else if (!string.IsNullOrEmpty(domain))
                        accountName = domain;
                    else
                        continue;
                }
                else
                {
                    continue;
                }

                if (peUse == SID_NAME_USE.Alias || peUse == SID_NAME_USE.WellKnownGroup)
                {
                    result.Add(sid);
                    Console.WriteLine("[+] \"{0}\" is added as an extra group.", accountName);
                    Console.WriteLine("    |-> SID  : {0}", sid);
                    Console.WriteLine("    |-> Type : {0}", peUse);
                }
                else
                {
                    Console.WriteLine("[-] \"{0}\" is not group account. Ignored.", accountName);
                    Console.WriteLine("    |-> SID  : {0}", sid);
                    Console.WriteLine("    |-> Type : {0}", peUse);
                }
            }

            return result.ToArray();
        }


        public static bool ConvertSidStringToAccountName(
            ref string sid,
            out string accountName,
            out string domainName,
            out SID_NAME_USE peUse)
        {
            var status = false;
            sid = sid.ToUpper();

            if (NativeMethods.ConvertStringSidToSid(sid, out IntPtr pSid))
            {
                status = ConvertSidToAccountName(pSid, out accountName, out domainName, out peUse);
                NativeMethods.LocalFree(pSid);
            }
            else
            {
                accountName = null;
                domainName = null;
                peUse = SID_NAME_USE.Unknown;
            }

            return status;
        }


        public static bool ConvertSidToAccountName(
            IntPtr pSid,
            out string accountName,
            out string domainName,
            out SID_NAME_USE sidType)
        {
            int nAccountNameLength = 255;
            int nDomainNameLength = 255;
            var accountNameBuilder = new StringBuilder(nAccountNameLength);
            var domainNameBuilder = new StringBuilder(nDomainNameLength);
            bool status = NativeMethods.LookupAccountSid(
                null,
                pSid,
                accountNameBuilder,
                ref nAccountNameLength,
                domainNameBuilder,
                ref nDomainNameLength,
                out sidType);

            if (status)
            {
                accountName = accountNameBuilder.ToString();
                domainName = domainNameBuilder.ToString();
            }
            else
            {
                accountName = null;
                domainName = null;
                sidType = SID_NAME_USE.Unknown;
            }

            return status;
        }


        public static IntPtr GetInformationFromToken(
            IntPtr hToken,
            TOKEN_INFORMATION_CLASS tokenInfoClass)
        {
            bool status;
            int error;
            int length = 4;
            IntPtr buffer;

            do
            {
                buffer = Marshal.AllocHGlobal(length);
                ZeroMemory(buffer, length);
                status = NativeMethods.GetTokenInformation(
                    hToken, tokenInfoClass, buffer, length, out length);
                error = Marshal.GetLastWin32Error();

                if (!status)
                    Marshal.FreeHGlobal(buffer);
            } while (!status && (error == Win32Consts.ERROR_INSUFFICIENT_BUFFER || error == Win32Consts.ERROR_BAD_LENGTH));

            if (!status)
                return IntPtr.Zero;

            return buffer;
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


        public static NTSTATUS RemoveSidMapping(string domain, string username)
        {
            NTSTATUS ntstatus;
            var input = new LSA_SID_NAME_MAPPING_OPERATION_REMOVE_INPUT();
            IntPtr pInputBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(input));

            if (!string.IsNullOrEmpty(domain))
                input.DomainName = new UNICODE_STRING(domain);

            if (!string.IsNullOrEmpty(username))
                input.AccountName = new UNICODE_STRING(username);

            Marshal.StructureToPtr(input, pInputBuffer, false);
            ntstatus = NativeMethods.LsaManageSidNameMapping(
                LSA_SID_NAME_MAPPING_OPERATION_TYPE.Remove,
                pInputBuffer,
                out IntPtr output);
            Marshal.FreeHGlobal(pInputBuffer);

            if (output != IntPtr.Zero)
                NativeMethods.LsaFreeMemory(output);

            return ntstatus;
        }


        public static void ZeroMemory(IntPtr buffer, int size)
        {
            var nullBytes = new byte[size];
            Marshal.Copy(nullBytes, 0, buffer, size);
        }
    }
}
