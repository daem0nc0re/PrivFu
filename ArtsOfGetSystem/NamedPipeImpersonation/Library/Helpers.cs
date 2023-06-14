using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using NamedPipeImpersonation.Interop;

namespace NamedPipeImpersonation.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
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

                for (var idx = 0; idx < tokenPrivileges.PrivilegeCount; idx++)
                {
                    int cchName = 128;
                    var stringBuilder = new StringBuilder(cchName);

                    NativeMethods.LookupPrivilegeName(null, in tokenPrivileges.Privileges[idx].Luid, stringBuilder, ref cchName);
                    privileges.Add(stringBuilder.ToString(), (SE_PRIVILEGE_ATTRIBUTES)tokenPrivileges.Privileges[idx].Attributes);
                    stringBuilder.Clear();
                }

                Marshal.FreeHGlobal(pInformationBuffer);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetTokenUserName(out string user, out string domain, out string stringSid, out SID_NAME_USE peUse)
        {
            return GetTokenUserName(WindowsIdentity.GetCurrent().Token, out user, out domain, out stringSid, out peUse);
        }



        public static bool GetTokenUserName(
            IntPtr hToken,
            out string user,
            out string domain,
            out string stringSid,
            out SID_NAME_USE peUse)
        {
            NTSTATUS ntstatus;
            IntPtr pTokenInformation;
            var nInformationLength = (uint)Marshal.SizeOf(typeof(TOKEN_USER));
            var status = false;
            user = null;
            domain = null;
            stringSid = null;
            peUse = SID_NAME_USE.SidTypeUnknown;

            do
            {
                pTokenInformation = Marshal.AllocHGlobal((int)nInformationLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenUser,
                    pTokenInformation,
                    nInformationLength,
                    out nInformationLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pTokenInformation);
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                int cchName = 255;
                int cchReferencedDomainName = 255;
                var userName = new StringBuilder(cchName);
                var domainName = new StringBuilder(cchReferencedDomainName);
                var tokenUser = (TOKEN_USER)Marshal.PtrToStructure(pTokenInformation, typeof(TOKEN_USER));
                status = NativeMethods.ConvertSidToStringSid(tokenUser.User.Sid, out stringSid);

                if (!status)
                {
                    stringSid = null;
                }
                else
                {
                    status = NativeMethods.LookupAccountSid(
                        null,
                        tokenUser.User.Sid,
                        userName,
                        ref cchName,
                        domainName,
                        ref cchReferencedDomainName,
                        out peUse);

                    if (status && (cchName > 0))
                        user = userName.ToString();
                    else
                        user = null;

                    if (status && (cchReferencedDomainName > 0))
                        domain = domainName.ToString();
                    else
                        domain = null;
                }

                Marshal.FreeHGlobal(pTokenInformation);
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
