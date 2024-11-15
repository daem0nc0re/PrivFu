using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using SwitchPriv.Interop;

namespace SwitchPriv.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static bool GetFullPrivilegeName(
            string filter,
            out List<SE_PRIVILEGE_ID> candidatePrivs)
        {
            candidatePrivs = new List<SE_PRIVILEGE_ID>();

            if (string.IsNullOrEmpty(filter))
                return false;

            for (var priv = SE_PRIVILEGE_ID.SeCreateTokenPrivilege; priv < SE_PRIVILEGE_ID.MaximumCount; priv++)
            {
                if (priv.ToString().IndexOf(filter, StringComparison.OrdinalIgnoreCase) != -1)
                    candidatePrivs.Add(priv);
            }

            return true;
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


        public static IntPtr GetProcessToken(int pid, TOKEN_TYPE tokenType)
        {
            NTSTATUS ntstatus;
            var hDupToken = IntPtr.Zero;
            var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(pid) };
            var objectAttributes = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
            };
            var nContextSize = Marshal.SizeOf(typeof(SECURITY_QUALITY_OF_SERVICE));
            var context = new SECURITY_QUALITY_OF_SERVICE
            {
                Length = nContextSize,
                ImpersonationLevel = SECURITY_IMPERSONATION_LEVEL.Impersonation
            };
            var pContextBuffer = Marshal.AllocHGlobal(nContextSize);
            Marshal.StructureToPtr(context, pContextBuffer, true);

            if (tokenType == TOKEN_TYPE.Impersonation)
                objectAttributes.SecurityQualityOfService = pContextBuffer;

            do
            {
                ntstatus = NativeMethods.NtOpenProcess(
                    out IntPtr hProcess,
                    ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                    in objectAttributes,
                    in clientId);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                ntstatus = NativeMethods.NtOpenProcessToken(
                    hProcess,
                    ACCESS_MASK.TOKEN_DUPLICATE,
                    out IntPtr hToken);
                NativeMethods.NtClose(hProcess);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                ntstatus = NativeMethods.NtDuplicateToken(
                    hToken,
                    ACCESS_MASK.MAXIMUM_ALLOWED,
                    in objectAttributes,
                    BOOLEAN.FALSE,
                    tokenType,
                    out hDupToken);
                NativeMethods.NtClose(hToken);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    hDupToken = IntPtr.Zero;
            } while (false);

            ntstatus = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(ntstatus);
            Marshal.FreeHGlobal(pContextBuffer);

            return hDupToken;
        }


        public static bool GetSidAccountName(
            IntPtr pSid,
            out string stringSid,
            out string accountName,
            out SID_NAME_USE sidType)
        {
            bool bSuccess;
            long nAuthority = 0;
            var nSubAuthorityCount = (int)Marshal.ReadByte(pSid, 1);
            var stringSidBuilder = new StringBuilder("S-");
            var nameBuilder = new StringBuilder(255);
            var domainBuilder = new StringBuilder(255);
            int nNameLength = 255;
            int nDomainLength = 255;
            accountName = null;

            for (int idx = 0; idx < 6; idx++)
            {
                nAuthority <<= 8;
                nAuthority |= (long)Marshal.ReadByte(pSid, 2 + idx);
            }

            stringSidBuilder.AppendFormat("{0}-{1}", Marshal.ReadByte(pSid), nAuthority);

            for (int idx = 0; idx < nSubAuthorityCount; idx++)
                stringSidBuilder.AppendFormat("-{0}", (uint)Marshal.ReadInt32(pSid, 8 + (idx * 4)));

            stringSid = stringSidBuilder.ToString();
            bSuccess = NativeMethods.LookupAccountSid(
                null,
                pSid,
                nameBuilder,
                ref nNameLength,
                domainBuilder,
                ref nDomainLength,
                out sidType);

            if (bSuccess)
            {
                if ((nNameLength > 0) && (nDomainLength > 0))
                    accountName = string.Format(@"{0}\{1}", domainBuilder.ToString(), nameBuilder.ToString());
                else if (nNameLength > 0)
                    accountName = nameBuilder.ToString();
                else if (nDomainLength > 0)
                    accountName = domainBuilder.ToString();
            }

            return bSuccess;
        }


        public static bool GetTokenIntegrityLevel(
            IntPtr hToken,
            out string stringSid,
            out string labelName,
            out SID_NAME_USE sidType)
        {
            var nInfoLength = 0x400u;
            var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                pInfoBuffer,
                nInfoLength,
                out uint _);
            stringSid = null;
            labelName = null;
            sidType = SID_NAME_USE.Unknown;

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var info = (TOKEN_MANDATORY_LABEL)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(TOKEN_MANDATORY_LABEL));
                GetSidAccountName(info.Label.Sid, out stringSid, out labelName, out sidType);
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetTokenPrivileges(
            IntPtr hToken,
            out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> privileges)
        {
            int nDosErrorCode;
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

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);
            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static string GetWin32ErrorMessage(int code)
        {
            int nSizeMesssage = 256;
            var message = new StringBuilder(nSizeMesssage);
            var dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            int nReturnedLength = NativeMethods.FormatMessage(
                dwFlags,
                IntPtr.Zero,
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


        public static bool ImpersonateThreadToken(IntPtr hThread, IntPtr hToken)
        {
            NTSTATUS ntstatus;
            int nDosErrorCode;
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            var bSuccess = false;
            Marshal.WriteIntPtr(pInfoBuffer, IntPtr.Zero);

            do
            {
                SECURITY_IMPERSONATION_LEVEL originalLevel;
                SECURITY_IMPERSONATION_LEVEL grantedLevel;
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenImpersonationLevel,
                    pInfoBuffer,
                    4u,
                    out uint _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;
                else
                    originalLevel = (SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(pInfoBuffer);

                Marshal.WriteIntPtr(pInfoBuffer, hToken);
                ntstatus = NativeMethods.NtSetInformationThread(
                    hThread,
                    THREADINFOCLASS.ThreadImpersonationToken,
                    pInfoBuffer,
                    (uint)IntPtr.Size);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                NativeMethods.NtQueryInformationToken(
                    WindowsIdentity.GetCurrent().Token,
                    TOKEN_INFORMATION_CLASS.TokenImpersonationLevel,
                    pInfoBuffer,
                    4u,
                    out uint _);
                grantedLevel = (SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(pInfoBuffer);
                bSuccess = (grantedLevel == originalLevel);

                if (bSuccess)
                    ntstatus = Win32Consts.STATUS_PRIVILEGE_NOT_HELD;
            } while (false);

            Marshal.FreeHGlobal(pInfoBuffer);
            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError((int)ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return bSuccess;
        }


        public static bool RevertThreadToken(IntPtr hThread)
        {
            int nDosErrorCode;
            NTSTATUS ntstatus;
            var pInfoBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pInfoBuffer, IntPtr.Zero);
            ntstatus = NativeMethods.NtSetInformationThread(
                hThread,
                THREADINFOCLASS.ThreadImpersonationToken,
                pInfoBuffer,
                (uint)IntPtr.Size);
            Marshal.FreeHGlobal(pInfoBuffer);
            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
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
            outputBuilder.Append("Example :\n\n");
            outputBuilder.Append("    * Down a specific process' integrity level to Low.\n\n");
            outputBuilder.AppendFormat("        PS C:\\> .\\{0} -p 4142 -s 1\n\n", AppDomain.CurrentDomain.FriendlyName);
            outputBuilder.Append("Protected and Secure level should not be available, but left for research purpose.\n\n");

            Console.WriteLine(outputBuilder.ToString());
        }
    }
}
