using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using SwitchPriv.Interop;

namespace SwitchPriv.Library
{
    internal class Helpers
    {
        public static string ConvertIndexToMandatoryLevelSid(int index)
        {
            if (index == (int)Globals.MANDATORY_LEVEL_INDEX.UNTRUSTED_MANDATORY_LEVEL)
                return Win32Consts.UNTRUSTED_MANDATORY_LEVEL;
            else if (index == (int)Globals.MANDATORY_LEVEL_INDEX.LOW_MANDATORY_LEVEL)
                return Win32Consts.LOW_MANDATORY_LEVEL;
            else if (index == (int)Globals.MANDATORY_LEVEL_INDEX.MEDIUM_MANDATORY_LEVEL)
                return Win32Consts.MEDIUM_MANDATORY_LEVEL;
            else if (index == (int)Globals.MANDATORY_LEVEL_INDEX.MEDIUM_PLUS_MANDATORY_LEVEL)
                return Win32Consts.MEDIUM_PLUS_MANDATORY_LEVEL;
            else if (index == (int)Globals.MANDATORY_LEVEL_INDEX.HIGH_MANDATORY_LEVEL)
                return Win32Consts.HIGH_MANDATORY_LEVEL;
            else if (index == (int)Globals.MANDATORY_LEVEL_INDEX.SYSTEM_MANDATORY_LEVEL)
                return Win32Consts.SYSTEM_MANDATORY_LEVEL;
            else if (index == (int)Globals.MANDATORY_LEVEL_INDEX.PROTECTED_MANDATORY_LEVEL)
                return Win32Consts.PROTECTED_MANDATORY_LEVEL;
            else if (index == (int)Globals.MANDATORY_LEVEL_INDEX.SECURE_MANDATORY_LEVEL)
                return Win32Consts.SECURE_MANDATORY_LEVEL;
            else
                return null;
        }


        public static string ConvertStringSidToMandatoryLevelName(string stringSid)
        {
            StringComparison opt = StringComparison.OrdinalIgnoreCase;

            if (string.Compare(stringSid, Win32Consts.UNTRUSTED_MANDATORY_LEVEL, opt) == 0)
                return "UNTRUSTED_MANDATORY_LEVEL";
            else if (string.Compare(stringSid, Win32Consts.LOW_MANDATORY_LEVEL, opt) == 0)
                return "LOW_MANDATORY_LEVEL";
            else if (string.Compare(stringSid, Win32Consts.MEDIUM_MANDATORY_LEVEL, opt) == 0)
                return "MEDIUM_MANDATORY_LEVEL";
            else if (string.Compare(stringSid, Win32Consts.MEDIUM_PLUS_MANDATORY_LEVEL, opt) == 0)
                return "MEDIUM_PLUS_MANDATORY_LEVEL";
            else if (string.Compare(stringSid, Win32Consts.HIGH_MANDATORY_LEVEL, opt) == 0)
                return "HIGH_MANDATORY_LEVEL";
            else if (string.Compare(stringSid, Win32Consts.SYSTEM_MANDATORY_LEVEL, opt) == 0)
                return "SYSTEM_MANDATORY_LEVEL";
            else if (string.Compare(stringSid, Win32Consts.PROTECTED_MANDATORY_LEVEL, opt) == 0)
                return "PROTECTED_MANDATORY_LEVEL";
            else if (string.Compare(stringSid, Win32Consts.SECURE_MANDATORY_LEVEL, opt) == 0)
                return "SECURE_MANDATORY_LEVEL";
            else
                return null;
        }


        public static string GetFullPrivilegeName(string shortenName)
        {
            StringComparison opt = StringComparison.OrdinalIgnoreCase;

            if (string.Compare(shortenName, "CreateToken", opt) == 0)
                return "SeCreateTokenPrivilege";
            else if (string.Compare(shortenName, "AssignPrimaryToken", opt) == 0)
                return "SeAssignPrimaryTokenPrivilege";
            else if (string.Compare(shortenName, "LockMemory", opt) == 0)
                return "SeLockMemoryPrivilege";
            else if (string.Compare(shortenName, "IncreaseQuota", opt) == 0)
                return "SeIncreaseQuotaPrivilege";
            else if (string.Compare(shortenName, "MachineAccount", opt) == 0)
                return "SeMachineAccountPrivilege";
            else if (string.Compare(shortenName, "Tcb", opt) == 0)
                return "SeTcbPrivilege";
            else if (string.Compare(shortenName, "Security", opt) == 0)
                return "SeSecurityPrivilege";
            else if (string.Compare(shortenName, "TakeOwnership", opt) == 0)
                return "SeTakeOwnershipPrivilege";
            else if (string.Compare(shortenName, "LoadDriver", opt) == 0)
                return "SeLoadDriverPrivilege";
            else if (string.Compare(shortenName, "SystemProfile", opt) == 0)
                return "SeSystemProfilePrivilege";
            else if (string.Compare(shortenName, "Systemtime", opt) == 0)
                return "SeSystemtimePrivilege";
            else if (string.Compare(shortenName, "ProfileSingleProcess", opt) == 0)
                return "SeProfileSingleProcessPrivilege";
            else if (string.Compare(shortenName, "IncreaseBasePriority", opt) == 0)
                return "SeIncreaseBasePriorityPrivilege";
            else if (string.Compare(shortenName, "CreatePagefile", opt) == 0)
                return "SeCreatePagefilePrivilege";
            else if (string.Compare(shortenName, "CreatePermanent", opt) == 0)
                return "SeCreatePermanentPrivilege";
            else if (string.Compare(shortenName, "Backup", opt) == 0)
                return "SeBackupPrivilege";
            else if (string.Compare(shortenName, "Restore", opt) == 0)
                return "SeRestorePrivilege";
            else if (string.Compare(shortenName, "Shutdown", opt) == 0)
                return "SeShutdownPrivilege";
            else if (string.Compare(shortenName, "Debug", opt) == 0)
                return "SeDebugPrivilege";
            else if (string.Compare(shortenName, "Audit", opt) == 0)
                return "SeAuditPrivilege";
            else if (string.Compare(shortenName, "SystemEnvironment", opt) == 0)
                return "SeSystemEnvironmentPrivilege";
            else if (string.Compare(shortenName, "ChangeNotify", opt) == 0)
                return "SeChangeNotifyPrivilege";
            else if (string.Compare(shortenName, "RemoteShutdown", opt) == 0)
                return "SeRemoteShutdownPrivilege";
            else if (string.Compare(shortenName, "Undock", opt) == 0)
                return "SeUndockPrivilege";
            else if (string.Compare(shortenName, "SyncAgent", opt) == 0)
                return "SeSyncAgentPrivilege";
            else if (string.Compare(shortenName, "EnableDelegation", opt) == 0)
                return "SeEnableDelegationPrivilege";
            else if (string.Compare(shortenName, "ManageVolume", opt) == 0)
                return "SeManageVolumePrivilege";
            else if (string.Compare(shortenName, "Impersonate", opt) == 0)
                return "SeImpersonatePrivilege";
            else if (string.Compare(shortenName, "CreateGlobal", opt) == 0)
                return "SeCreateGlobalPrivilege";
            else if (string.Compare(shortenName, "TrustedCredManAccess", opt) == 0)
                return "SeTrustedCredManAccessPrivilege";
            else if (string.Compare(shortenName, "Relabel", opt) == 0)
                return "SeRelabelPrivilege";
            else if (string.Compare(shortenName, "IncreaseWorkingSet", opt) == 0)
                return "SeIncreaseWorkingSetPrivilege";
            else if (string.Compare(shortenName, "TimeZone", opt) == 0)
                return "SeTimeZonePrivilege";
            else if (string.Compare(shortenName, "CreateSymbolicLink", opt) == 0)
                return "SeCreateSymbolicLinkPrivilege";
            else if (string.Compare(shortenName, "DelegateSessionUserImpersonate", opt) == 0)
                return "SeDelegateSessionUserImpersonatePrivilege";
            else
                return null;
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


        public static bool IsPrivilegeEnabled(
            IntPtr hToken,
            LUID priv,
            out bool isEnabled)
        {
            int error;
            isEnabled = false;

            if (hToken == IntPtr.Zero)
                return false;

            var privSet = new PRIVILEGE_SET(1, Win32Consts.PRIVILEGE_SET_ALL_NECESSARY);
            privSet.Privilege[0].Luid = priv;
            privSet.Privilege[0].Attributes = (uint)PrivilegeAttributeFlags.SE_PRIVILEGE_ENABLED;

            IntPtr pPrivileges = Marshal.AllocHGlobal(Marshal.SizeOf(privSet));
            Marshal.StructureToPtr(privSet, pPrivileges, true);

            if (!NativeMethods.PrivilegeCheck(
                hToken,
                pPrivileges,
                out isEnabled))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to check the target privilege is enabled.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));
                Marshal.FreeHGlobal(pPrivileges);

                return false;
            }

            Marshal.FreeHGlobal(pPrivileges);

            return true;
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


        public static void ZeroMemory(IntPtr buffer, int size)
        {
            var nullBytes = new byte[size];
            Marshal.Copy(nullBytes, 0, buffer, size);
        }
    }
}
