using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using UserRightsUtil.Interop;

namespace UserRightsUtil.Library
{
    class Helpers
    {
        public static string ConvertAccountNameToSidString(
            ref string accountName,
            out Win32Const.SID_NAME_USE peUse)
        {
            int error;
            bool status;
            string username;
            string domain;
            Regex rx1 = new Regex(
                @"^[^\\]+\\[^\\]+$",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);
            Regex rx2 = new Regex(
                @"^[^\\]+$",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);
            IntPtr pSid;
            int cbSid = 8;
            StringBuilder referencedDomainName = new StringBuilder();
            int cchReferencedDomainName = 8;
            peUse = 0;

            if (rx1.IsMatch(accountName))
            {
                try
                {
                    domain = accountName.Split('\\')[0];
                    username = accountName.Split('\\')[1];

                    if (domain == ".")
                    {
                        accountName = string.Format(
                            "{0}\\{1}",
                            Environment.MachineName,
                            username);
                    }
                }
                catch
                {
                    return null;
                }
            }
            else if (!rx2.IsMatch(accountName))
            {
                return null;
            }

            do
            {
                referencedDomainName.Capacity = cchReferencedDomainName;
                pSid = Marshal.AllocHGlobal(cbSid);
                ZeroMemory(pSid, cbSid);

                status = Win32Api.LookupAccountName(
                    null,
                    accountName,
                    pSid,
                    ref cbSid,
                    referencedDomainName,
                    ref cchReferencedDomainName,
                    out peUse);
                error = Marshal.GetLastWin32Error();

                if (!status)
                {
                    referencedDomainName.Clear();
                    Marshal.FreeHGlobal(pSid);
                }
            } while (!status && error == Win32Const.ERROR_INSUFFICIENT_BUFFER);

            if (!status)
                return null;

            if (!Win32Api.IsValidSid(pSid))
                return null;

            accountName = ConvertSidToAccountName(pSid, out peUse);

            if (Win32Api.ConvertSidToStringSid(pSid, out string strSid))
            {
                Win32Api.LocalFree(pSid);

                return strSid;
            }
            else
            {
                Win32Api.LocalFree(pSid);

                return null;
            }
        }


        public static string ConvertSidStringToAccountName(
            ref string sid,
            out Win32Const.SID_NAME_USE peUse)
        {
            string accountName;

            if (!Win32Api.ConvertStringSidToSid(sid, out IntPtr pSid))
            {
                peUse = 0;
                return null;
            }

            accountName = ConvertSidToAccountName(pSid, out peUse);
            Win32Api.LocalFree(pSid);

            return accountName;
        }


        public static string ConvertSidToAccountName(
            IntPtr pSid,
            out Win32Const.SID_NAME_USE peUse)
        {
            StringComparison opt = StringComparison.OrdinalIgnoreCase;
            bool status;
            int error;
            StringBuilder pName = new StringBuilder();
            int cchName = 4;
            StringBuilder pReferencedDomainName = new StringBuilder();
            int cchReferencedDomainName = 4;

            do
            {
                pName.Capacity = cchName;
                pReferencedDomainName.Capacity = cchReferencedDomainName;

                status = Win32Api.LookupAccountSid(
                    null,
                    pSid,
                    pName,
                    ref cchName,
                    pReferencedDomainName,
                    ref cchReferencedDomainName,
                    out peUse);
                error = Marshal.GetLastWin32Error();

                if (!status)
                {
                    pName.Clear();
                    pReferencedDomainName.Clear();
                }
            } while (!status && error == Win32Const.ERROR_INSUFFICIENT_BUFFER);

            if (!status)
                return null;

            if (string.Compare(pName.ToString(), pReferencedDomainName.ToString(), opt) == 0)
            {
                return pReferencedDomainName.ToString();
            }
            else
            {
                return string.Format("{0}\\{1}",
                    pReferencedDomainName.ToString(),
                    pName.ToString());
            }
        }


        public static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            var message = new StringBuilder();
            var messageSize = 255;
            Win32Const.FormatMessageFlags messageFlag;
            IntPtr pNtdll;
            message.Capacity = messageSize;

            if (isNtStatus)
            {
                pNtdll = Win32Api.LoadLibrary("ntdll.dll");
                messageFlag = Win32Const.FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE |
                    Win32Const.FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }
            else
            {
                pNtdll = IntPtr.Zero;
                messageFlag = Win32Const.FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }

            uint ret = Win32Api.FormatMessage(
                messageFlag,
                pNtdll,
                code,
                0,
                message,
                messageSize,
                IntPtr.Zero);

            if (isNtStatus)
                Win32Api.FreeLibrary(pNtdll);

            if (ret == 0)
            {
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            }
            else
            {
                return string.Format(
                    "[ERROR] Code 0x{0} : {1}",
                    code.ToString("X8"),
                    message.ToString().Trim());
            }
        }


        public static void ZeroMemory(IntPtr buffer, int size)
        {
            var nullBytes = new byte[size];
            Marshal.Copy(nullBytes, 0, buffer, size);
        }
    }
}
