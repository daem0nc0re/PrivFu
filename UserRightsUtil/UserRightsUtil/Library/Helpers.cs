using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using UserRightsUtil.Interop;

namespace UserRightsUtil.Library
{
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


        public static string ConvertSidToAccountName(
            IntPtr pSid,
            out SID_NAME_USE sidType)
        {
            string accountName = null;

            if (ConvertSidToAccountName(
                pSid,
                out string name,
                out string domain,
                out sidType))
            {
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
    }
}
