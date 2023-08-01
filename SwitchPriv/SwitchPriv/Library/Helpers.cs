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


        public static string GetFullPrivilegeName(string shortenName)
        {
            if (CompareIgnoreCase(shortenName, "CreateToken"))
                return "SeCreateTokenPrivilege";
            else if (CompareIgnoreCase(shortenName, "AssignPrimaryToken"))
                return "SeAssignPrimaryTokenPrivilege";
            else if (CompareIgnoreCase(shortenName, "LockMemory"))
                return "SeLockMemoryPrivilege";
            else if (CompareIgnoreCase(shortenName, "IncreaseQuota"))
                return "SeIncreaseQuotaPrivilege";
            else if (CompareIgnoreCase(shortenName, "MachineAccount"))
                return "SeMachineAccountPrivilege";
            else if (CompareIgnoreCase(shortenName, "Tcb"))
                return "SeTcbPrivilege";
            else if (CompareIgnoreCase(shortenName, "Security"))
                return "SeSecurityPrivilege";
            else if (CompareIgnoreCase(shortenName, "TakeOwnership"))
                return "SeTakeOwnershipPrivilege";
            else if (CompareIgnoreCase(shortenName, "LoadDriver"))
                return "SeLoadDriverPrivilege";
            else if (CompareIgnoreCase(shortenName, "SystemProfile"))
                return "SeSystemProfilePrivilege";
            else if (CompareIgnoreCase(shortenName, "Systemtime"))
                return "SeSystemtimePrivilege";
            else if (CompareIgnoreCase(shortenName, "ProfileSingleProcess"))
                return "SeProfileSingleProcessPrivilege";
            else if (CompareIgnoreCase(shortenName, "IncreaseBasePriority"))
                return "SeIncreaseBasePriorityPrivilege";
            else if (CompareIgnoreCase(shortenName, "CreatePagefile"))
                return "SeCreatePagefilePrivilege";
            else if (CompareIgnoreCase(shortenName, "CreatePermanent"))
                return "SeCreatePermanentPrivilege";
            else if (CompareIgnoreCase(shortenName, "Backup"))
                return "SeBackupPrivilege";
            else if (CompareIgnoreCase(shortenName, "Restore"))
                return "SeRestorePrivilege";
            else if (CompareIgnoreCase(shortenName, "Shutdown"))
                return "SeShutdownPrivilege";
            else if (CompareIgnoreCase(shortenName, "Debug"))
                return "SeDebugPrivilege";
            else if (CompareIgnoreCase(shortenName, "Audit"))
                return "SeAuditPrivilege";
            else if (CompareIgnoreCase(shortenName, "SystemEnvironment"))
                return "SeSystemEnvironmentPrivilege";
            else if (CompareIgnoreCase(shortenName, "ChangeNotify"))
                return "SeChangeNotifyPrivilege";
            else if (CompareIgnoreCase(shortenName, "RemoteShutdown"))
                return "SeRemoteShutdownPrivilege";
            else if (CompareIgnoreCase(shortenName, "Undock"))
                return "SeUndockPrivilege";
            else if (CompareIgnoreCase(shortenName, "SyncAgent"))
                return "SeSyncAgentPrivilege";
            else if (CompareIgnoreCase(shortenName, "EnableDelegation"))
                return "SeEnableDelegationPrivilege";
            else if (CompareIgnoreCase(shortenName, "ManageVolume"))
                return "SeManageVolumePrivilege";
            else if (CompareIgnoreCase(shortenName, "Impersonate"))
                return "SeImpersonatePrivilege";
            else if (CompareIgnoreCase(shortenName, "CreateGlobal"))
                return "SeCreateGlobalPrivilege";
            else if (CompareIgnoreCase(shortenName, "TrustedCredManAccess"))
                return "SeTrustedCredManAccessPrivilege";
            else if (CompareIgnoreCase(shortenName, "Relabel"))
                return "SeRelabelPrivilege";
            else if (CompareIgnoreCase(shortenName, "IncreaseWorkingSet"))
                return "SeIncreaseWorkingSetPrivilege";
            else if (CompareIgnoreCase(shortenName, "TimeZone"))
                return "SeTimeZonePrivilege";
            else if (CompareIgnoreCase(shortenName, "CreateSymbolicLink"))
                return "SeCreateSymbolicLinkPrivilege";
            else if (CompareIgnoreCase(shortenName, "DelegateSessionUserImpersonate"))
                return "SeDelegateSessionUserImpersonatePrivilege";
            else
                return null;
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
            Console.WriteLine();
            Console.WriteLine("Available values for --enable, --disable, and --remove options:");
            Console.WriteLine("    + CreateToken                    : Specifies SeCreateTokenPrivilege.");
            Console.WriteLine("    + AssignPrimaryToken             : Specifies SeAssignPrimaryTokenPrivilege.");
            Console.WriteLine("    + LockMemory                     : Specifies SeLockMemoryPrivilege.");
            Console.WriteLine("    + IncreaseQuota                  : Specifies SeIncreaseQuotaPrivilege.");
            Console.WriteLine("    + MachineAccount                 : Specifies SeMachineAccountPrivilege.");
            Console.WriteLine("    + Tcb                            : Specifies SeTcbPrivilege.");
            Console.WriteLine("    + Security                       : Specifies SeSecurityPrivilege.");
            Console.WriteLine("    + TakeOwnership                  : Specifies SeTakeOwnershipPrivilege.");
            Console.WriteLine("    + LoadDriver                     : Specifies SeLoadDriverPrivilege.");
            Console.WriteLine("    + SystemProfile                  : Specifies SeSystemProfilePrivilege.");
            Console.WriteLine("    + Systemtime                     : Specifies SeSystemtimePrivilege.");
            Console.WriteLine("    + ProfileSingle                  : Specifies SeProfileSingleProcessPrivilege.");
            Console.WriteLine("    + IncreaseBasePriority           : Specifies SeIncreaseBasePriorityPrivilege.");
            Console.WriteLine("    + CreatePagefile                 : Specifies SeCreatePagefilePrivilege.");
            Console.WriteLine("    + CreatePermanent                : Specifies SeCreatePermanentPrivilege.");
            Console.WriteLine("    + Backup                         : Specifies SeBackupPrivilege.");
            Console.WriteLine("    + Restore                        : Specifies SeRestorePrivilege.");
            Console.WriteLine("    + Shutdown                       : Specifies SeShutdownPrivilege.");
            Console.WriteLine("    + Debug                          : Specifies SeDebugPrivilege.");
            Console.WriteLine("    + Audit                          : Specifies SeAuditPrivilege.");
            Console.WriteLine("    + SystemEnvironment              : Specifies SeSystemEnvironmentPrivilege.");
            Console.WriteLine("    + ChangeNotify                   : Specifies SeChangeNotifyPrivilege.");
            Console.WriteLine("    + RemoteShutdown                 : Specifies SeRemoteShutdownPrivilege.");
            Console.WriteLine("    + Undock                         : Specifies SeUndockPrivilege.");
            Console.WriteLine("    + SyncAgent                      : Specifies SeSyncAgentPrivilege.");
            Console.WriteLine("    + EnableDelegation               : Specifies SeEnableDelegationPrivilege.");
            Console.WriteLine("    + ManageVolume                   : Specifies SeManageVolumePrivilege.");
            Console.WriteLine("    + Impersonate                    : Specifies SeImpersonatePrivilege.");
            Console.WriteLine("    + CreateGlobal                   : Specifies SeCreateGlobalPrivilege.");
            Console.WriteLine("    + TrustedCredManAccess           : Specifies SeTrustedCredManAccessPrivilege.");
            Console.WriteLine("    + Relabel                        : Specifies SeRelabelPrivilege.");
            Console.WriteLine("    + IncreaseWorkingSet             : Specifies SeIncreaseWorkingSetPrivilege.");
            Console.WriteLine("    + TimeZone                       : Specifies SeTimeZonePrivilege.");
            Console.WriteLine("    + CreateSymbolicLink             : Specifies SeCreateSymbolicLinkPrivilege.");
            Console.WriteLine("    + DelegateSessionUserImpersonate : Specifies SeDelegateSessionUserImpersonatePrivilege.");
            Console.WriteLine("    + All                            : Specifies all token privileges.");
            Console.WriteLine();
            Console.WriteLine("Available values for --integrity option:");
            Console.WriteLine("    + 0 : UNTRUSTED_MANDATORY_LEVEL");
            Console.WriteLine("    + 1 : LOW_MANDATORY_LEVEL");
            Console.WriteLine("    + 2 : MEDIUM_MANDATORY_LEVEL");
            Console.WriteLine("    + 3 : MEDIUM_PLUS_MANDATORY_LEVEL");
            Console.WriteLine("    + 4 : HIGH_MANDATORY_LEVEL");
            Console.WriteLine("    + 5 : SYSTEM_MANDATORY_LEVEL");
            Console.WriteLine("    + 6 : PROTECTED_MANDATORY_LEVEL");
            Console.WriteLine("    + 7 : SECURE_MANDATORY_LEVEL");
            Console.WriteLine();
        }


        public static void ZeroMemory(IntPtr pBuffer, int nSize)
        {
            for (var offset = 0; offset < nSize; offset++)
                Marshal.WriteByte(pBuffer, offset, 0);
        }
    }
}
