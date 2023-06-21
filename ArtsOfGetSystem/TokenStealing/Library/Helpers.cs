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


        public static string GetTokenUserSid(IntPtr hToken)
        {
            NTSTATUS ntstatus;
            string stringSid = null;
            IntPtr pTokenInformation;
            var nInformationLength = (uint)Marshal.SizeOf(typeof(TOKEN_USER));

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
                var tokenUser = (TOKEN_USER)Marshal.PtrToStructure(pTokenInformation, typeof(TOKEN_USER));
                bool status = NativeMethods.ConvertSidToStringSid(tokenUser.User.Sid, out stringSid);
                Marshal.FreeHGlobal(pTokenInformation);

                if (!status)
                    stringSid = null;
            }

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
