using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using TokenStealing.Interop;

namespace TokenStealing.Library
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
            var nInformationLength = Marshal.SizeOf(typeof(TOKEN_PRIVILEGES));
            privileges = new Dictionary<string, SE_PRIVILEGE_ATTRIBUTES>();

            do
            {
                pInformationBuffer = Marshal.AllocHGlobal(nInformationLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenPrivileges,
                    pInformationBuffer,
                    (uint)nInformationLength,
                    out uint nRequiredLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Marshal.FreeHGlobal(pInformationBuffer);
                    nInformationLength = (int)nRequiredLength;
                    pInformationBuffer = IntPtr.Zero;
                }
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
            }

            if (pInformationBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(pInformationBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static string GetTokenUserSid(IntPtr hToken)
        {
            NTSTATUS ntstatus;
            bool status;
            string stringSid = null;
            IntPtr pTokenInformation;
            var nInformationLength = Marshal.SizeOf(typeof(TOKEN_USER));

            do
            {
                pTokenInformation = Marshal.AllocHGlobal(nInformationLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenUser,
                    pTokenInformation,
                    (uint)nInformationLength,
                    out uint nRequreidLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Marshal.FreeHGlobal(pTokenInformation);
                    nInformationLength = (int)nRequreidLength;
                    pTokenInformation = IntPtr.Zero;
                }
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var tokenUser = (TOKEN_USER)Marshal.PtrToStructure(pTokenInformation, typeof(TOKEN_USER));
                status = NativeMethods.ConvertSidToStringSid(tokenUser.User.Sid, out stringSid);

                if (!status)
                    stringSid = null;
            }

            if (pTokenInformation != IntPtr.Zero)
                Marshal.FreeHGlobal(pTokenInformation);

            return stringSid;
        }


        public static bool IsSystem()
        {
            return IsSystem(WindowsIdentity.GetCurrent().Token);
        }


        public static bool IsSystem(IntPtr hToken)
        {
            return CompareIgnoreCase(GetTokenUserSid(hToken), "S-1-5-18");
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
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            else
                return string.Format("[ERROR] Code 0x{0} : {1}", code.ToString("X8"), message.ToString().Trim());
        }
    }
}
