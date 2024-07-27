using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using SwitchPriv.Interop;

namespace SwitchPriv.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        public static string ConvertIntegrityLeveSidToAccountName(IntPtr pSid)
        {
            string integrityLevel = "N/A";

            // Verify SID = S-1-16-XXXX
            if (Marshal.ReadInt64(pSid) == 0x10000000_00000101L)
            {
                int nNameLength = 255;
                int nDomainNameLength = 255;
                var nameBuilder = new StringBuilder(nNameLength);
                var domainNameBuilder = new StringBuilder(nDomainNameLength);
                var status = NativeMethods.LookupAccountSid(
                    null,
                    pSid,
                    nameBuilder,
                    ref nNameLength,
                    domainNameBuilder,
                    ref nDomainNameLength,
                    out SID_NAME_USE _);

                if (status)
                    integrityLevel = nameBuilder.ToString();
            }

            return integrityLevel;
        }


        public static bool GetFullPrivilegeName(
            string filter,
            out List<string> candidatePrivs)
        {
            candidatePrivs = new List<string>();

            if (string.IsNullOrEmpty(filter))
                return false;

            for (var priv = SE_PRIVILEGE_ID.MinimumIndex; priv < SE_PRIVILEGE_ID.MaximumCount; priv++)
            {
                if (priv.ToString().IndexOf(filter, StringComparison.OrdinalIgnoreCase) != -1)
                    candidatePrivs.Add(priv.ToString());
            }

            return true;
        }


        public static int GetParentProcessId()
        {
            return GetParentProcessId(Process.GetCurrentProcess().Handle);
        }


        public static int GetParentProcessId(IntPtr hProcess)
        {
            NTSTATUS ntstatus;
            int ppid = -1;
            var nInfoSize = Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            var pInfoBuffer = Marshal.AllocHGlobal(nInfoSize);

            ntstatus = NativeMethods.NtQueryInformationProcess(
                hProcess,
                PROCESSINFOCLASS.ProcessBasicInformation,
                pInfoBuffer,
                (uint)nInfoSize,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(PROCESS_BASIC_INFORMATION));
                ppid = pbi.InheritedFromUniqueProcessId.ToInt32();
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return ppid;
        }


        public static string GetTokenIntegrityLevelString(IntPtr hToken)
        {
            NTSTATUS ntstatus;
            bool status;
            IntPtr pInfoBuffer;
            string integrityLevel = "N/A";
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
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (!status)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (status)
            {
                var mandatoryLabel = (TOKEN_MANDATORY_LABEL)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(TOKEN_MANDATORY_LABEL));
                integrityLevel = ConvertIntegrityLeveSidToAccountName(mandatoryLabel.Label.Sid);

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return integrityLevel;
        }


        public static bool GetTokenPrivileges(
            IntPtr hToken,
            out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> privileges)
        {
            var nOffset = Marshal.OffsetOf(typeof(TOKEN_PRIVILEGES), "Privileges").ToInt32();
            var nUnitSize = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
            var nInfoLength = (uint)(nOffset + (nUnitSize * 36));
            var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenPrivileges,
                pInfoBuffer,
                nInfoLength,
                out uint _);
            privileges = new Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES>();

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                int nPrivilegeCount = Marshal.ReadInt32(pInfoBuffer);

                for (var idx = 0; idx < nPrivilegeCount; idx++)
                {
                    privileges.Add(
                        (SE_PRIVILEGE_ID)Marshal.ReadInt32(pInfoBuffer, nOffset),
                        (SE_PRIVILEGE_ATTRIBUTES)Marshal.ReadInt32(pInfoBuffer, nOffset + 8));
                    nOffset += nUnitSize;
                }
            }

            Marshal.FreeHGlobal(pInfoBuffer);

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


        public static void ListPrivilegeOptionValues()
        {
            var outputBuilder = new StringBuilder();

            outputBuilder.Append("\n");
            outputBuilder.Append("Available values for --integrity option:\n\n");
            outputBuilder.Append("    * 0 : UNTRUSTED_MANDATORY_LEVEL\n");
            outputBuilder.Append("    * 1 : LOW_MANDATORY_LEVEL\n");
            outputBuilder.Append("    * 2 : MEDIUM_MANDATORY_LEVEL\n");
            outputBuilder.Append("    * 3 : MEDIUM_PLUS_MANDATORY_LEVEL\n");
            outputBuilder.Append("    * 4 : HIGH_MANDATORY_LEVEL\n");
            outputBuilder.Append("    * 5 : SYSTEM_MANDATORY_LEVEL\n");
            outputBuilder.Append("    * 6 : PROTECTED_MANDATORY_LEVEL\n");
            outputBuilder.Append("    * 7 : SECURE_MANDATORY_LEVEL\n\n");
            outputBuilder.Append("Example :\n\n");
            outputBuilder.Append("    * Down a specific process' integrity level to Low.\n\n");
            outputBuilder.AppendFormat("        PS C:\\> .\\{0} -p 4142 -s 1\n\n", AppDomain.CurrentDomain.FriendlyName);
            outputBuilder.Append("Protected and Secure level should not be available, but left for research purpose.\n\n");

            Console.WriteLine(outputBuilder.ToString());
        }
    }
}
