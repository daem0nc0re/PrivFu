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
            var validNames = new List<string>
            {
                Win32Consts.SE_ASSIGNPRIMARYTOKEN_NAME,
                Win32Consts.SE_AUDIT_NAME,
                Win32Consts.SE_BACKUP_NAME,
                Win32Consts.SE_CHANGE_NOTIFY_NAME,
                Win32Consts.SE_CREATE_GLOBAL_NAME,
                Win32Consts.SE_CREATE_PAGEFILE_NAME,
                Win32Consts.SE_CREATE_PERMANENT_NAME,
                Win32Consts.SE_CREATE_SYMBOLIC_LINK_NAME,
                Win32Consts.SE_CREATE_TOKEN_NAME,
                Win32Consts.SE_DEBUG_NAME,
                Win32Consts.SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME,
                Win32Consts.SE_ENABLE_DELEGATION_NAME,
                Win32Consts.SE_IMPERSONATE_NAME,
                Win32Consts.SE_INCREASE_BASE_PRIORITY_NAME,
                Win32Consts.SE_INCREASE_QUOTA_NAME,
                Win32Consts.SE_INCREASE_WORKING_SET_NAME,
                Win32Consts.SE_LOAD_DRIVER_NAME,
                Win32Consts.SE_LOCK_MEMORY_NAME,
                Win32Consts.SE_MACHINE_ACCOUNT_NAME,
                Win32Consts.SE_MANAGE_VOLUME_NAME,
                Win32Consts.SE_PROFILE_SINGLE_PROCESS_NAME,
                Win32Consts.SE_RELABEL_NAME,
                Win32Consts.SE_REMOTE_SHUTDOWN_NAME,
                Win32Consts.SE_RESTORE_NAME,
                Win32Consts.SE_SECURITY_NAME,
                Win32Consts.SE_SHUTDOWN_NAME,
                Win32Consts.SE_SYNC_AGENT_NAME,
                Win32Consts.SE_SYSTEMTIME_NAME,
                Win32Consts.SE_SYSTEM_ENVIRONMENT_NAME,
                Win32Consts.SE_SYSTEM_PROFILE_NAME,
                Win32Consts.SE_TAKE_OWNERSHIP_NAME,
                Win32Consts.SE_TCB_NAME,
                Win32Consts.SE_TIME_ZONE_NAME,
                Win32Consts.SE_TRUSTED_CREDMAN_ACCESS_NAME,
                Win32Consts.SE_UNDOCK_NAME
            };
            candidatePrivs = new List<string>();

            if (string.IsNullOrEmpty(filter))
                return false;

            foreach (var priv in validNames)
            {
                if (priv.IndexOf(filter, StringComparison.OrdinalIgnoreCase) != -1)
                    candidatePrivs.Add(priv);
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


        public static string GetPrivilegeName(LUID priv)
        {
            string privilegeName = null;
            int cchName = 255;
            var name = new StringBuilder(cchName);

            if (NativeMethods.LookupPrivilegeName(null, in priv, name, ref cchName))
                privilegeName = name.ToString();

            return privilegeName;
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


        public static void ZeroMemory(IntPtr pBuffer, int nSize)
        {
            for (var offset = 0; offset < nSize; offset++)
                Marshal.WriteByte(pBuffer, offset, 0);
        }
    }
}
