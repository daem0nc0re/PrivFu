using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using S4uDelegator.Interop;

namespace S4uDelegator.Library
{
    internal class Helpers
    {
        public static string ConvertAccountNameToSidString(
            ref string accountName,
            out SID_NAME_USE peUse)
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

                status = NativeMethods.LookupAccountName(
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
            } while (!status && error == Win32Consts.ERROR_INSUFFICIENT_BUFFER);

            if (!status)
                return null;

            if (!NativeMethods.IsValidSid(pSid))
                return null;

            accountName = ConvertSidToAccountName(pSid, out peUse);

            if (NativeMethods.ConvertSidToStringSid(pSid, out string strSid))
            {
                NativeMethods.LocalFree(pSid);

                return strSid;
            }
            else
            {
                NativeMethods.LocalFree(pSid);

                return null;
            }
        }


        public static string ConvertSidStringToAccountName(
            ref string sid,
            out SID_NAME_USE peUse)
        {
            string accountName;
            sid = sid.ToUpper();

            if (!NativeMethods.ConvertStringSidToSid(sid, out IntPtr pSid))
            {
                peUse = 0;
                return null;
            }

            accountName = ConvertSidToAccountName(pSid, out peUse);
            NativeMethods.LocalFree(pSid);

            return accountName;
        }


        public static string ConvertSidToAccountName(
            IntPtr pSid,
            out SID_NAME_USE peUse)
        {
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

                status = NativeMethods.LookupAccountSid(
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
            } while (!status && error == Win32Consts.ERROR_INSUFFICIENT_BUFFER);

            if (!status)
                return null;

            if (peUse == SID_NAME_USE.SidTypeDomain)
            {
                return pReferencedDomainName.ToString();
            }
            else if (cchName == 0)
            {
                return pReferencedDomainName.ToString();
            }
            else if (cchReferencedDomainName == 0)
            {
                return pName.ToString();
            }
            else
            {
                return string.Format("{0}\\{1}",
                    pReferencedDomainName.ToString(),
                    pName.ToString());
            }
        }


        public static string GetCurrentDomain()
        {
            int error;
            bool status;
            var domain = new StringBuilder();
            var nSize = 0;

            do
            {
                status = NativeMethods.GetComputerNameEx(
                    COMPUTER_NAME_FORMAT.ComputerNameDnsDomain,
                    domain,
                    ref nSize);
                error = Marshal.GetLastWin32Error();

                if (!status)
                {
                    domain.Capacity = nSize;
                    domain.Clear();
                }
            } while (!status && error == Win32Consts.ERROR_MORE_DATA);

            if (!status || nSize == 0)
                return null;

            return domain.ToString();
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


        public static bool GetPrivilegeLuid(
            string privilegeName,
            out LUID luid)
        {
            int error;

            if (!NativeMethods.LookupPrivilegeValue(
                null,
                privilegeName,
                out luid))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to lookup {0}.", privilegeName);
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }

            return true;
        }


        public static string GetPrivilegeName(LUID priv)
        {
            int error;
            int cchName = 255;
            StringBuilder privilegeName = new StringBuilder(255);

            if (!NativeMethods.LookupPrivilegeName(
                null,
                ref priv,
                privilegeName,
                ref cchName))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to lookup privilege name.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return null;
            }

            return privilegeName.ToString();
        }


        public static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            int nReturnedLength;
            ProcessModuleCollection modules;
            FormatMessageFlags dwFlags;
            int nSizeMesssage = 256;
            var message = new StringBuilder(nSizeMesssage);
            IntPtr pNtdll = IntPtr.Zero;

            if (isNtStatus)
            {
                modules = Process.GetCurrentProcess().Modules;

                foreach (ProcessModule mod in modules)
                {
                    if (string.Compare(
                        Path.GetFileName(mod.FileName),
                        "ntdll.dll",
                        StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        pNtdll = mod.BaseAddress;
                        break;
                    }
                }

                dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE |
                    FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }
            else
            {
                dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
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
