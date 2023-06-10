using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using SwitchPriv.Interop;

namespace SwitchPriv.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static bool DisableSinglePrivilege(IntPtr hToken, string privName)
        {
            bool status = NativeMethods.LookupPrivilegeValue(null, privName, out LUID luid);

            if (status)
                status = DisableSinglePrivilege(hToken, luid);

            return status;
        }


        public static bool DisableSinglePrivilege(IntPtr hToken, LUID priv)
        {
            int error;
            bool status;
            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES(1);
            tp.Privileges[0].Luid = priv;
            tp.Privileges[0].Attributes = 0;
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            status = NativeMethods.AdjustTokenPrivileges(
                hToken,
                false,
                pTokenPrivilege,
                0,
                IntPtr.Zero,
                IntPtr.Zero);
            error = Marshal.GetLastWin32Error();
            status = (status && (error == 0));

            if (!status)
            {
                Console.WriteLine("[-] Failed to disable {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
            }

            return status;
        }


        public static bool EnableMultiplePrivileges(IntPtr hToken, string[] privs)
        {
            Dictionary<string, bool> results = new Dictionary<string, bool>();
            var privList = new List<string>(privs);
            bool isEnabled;
            bool enabledAll = true;
            Helpers.GetTokenPrivileges(hToken, out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

            foreach (var name in privList)
            {
                results.Add(name, false);
            }

            foreach (var priv in availablePrivs)
            {
                foreach (var name in privList)
                {
                    if (Helpers.CompareIgnoreCase(priv.Key, name))
                    {
                        isEnabled = ((priv.Value & SE_PRIVILEGE_ATTRIBUTES.ENABLED) != 0);
                        NativeMethods.LookupPrivilegeValue(null, priv.Key, out LUID luid);

                        if (isEnabled)
                            results[name] = true;
                        else
                            results[name] = EnableSinglePrivilege(hToken, luid);
                    }
                }
            }

            foreach (var result in results)
            {
                if (!result.Value)
                {
                    Console.WriteLine("[-] {0} is not available.", result.Key);
                    enabledAll = false;
                }
            }

            return enabledAll;
        }


        public static bool EnableSinglePrivilege(IntPtr hToken, string privilegeName)
        {
            bool status = NativeMethods.LookupPrivilegeValue(null, privilegeName, out LUID luid);

            if (status)
                status = EnableSinglePrivilege(hToken, luid);

            return status;
        }


        public static bool EnableSinglePrivilege(IntPtr hToken, LUID priv)
        {
            int error;
            bool status;
            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES(1);
            tp.Privileges[0].Luid = priv;
            tp.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.ENABLED;
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            status = NativeMethods.AdjustTokenPrivileges(
                hToken,
                false,
                pTokenPrivilege,
                0,
                IntPtr.Zero,
                IntPtr.Zero);
            error = Marshal.GetLastWin32Error();
            status = (status && (error == 0));

            if (!status)
            {
                Console.WriteLine("[-] Failed to enable {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
            }

            return status;
        }


        public static bool ImpersonateAsSmss()
        {
            return ImpersonateAsSmss(new string[] { });
        }


        public static bool ImpersonateAsSmss(string[] privs)
        {
            int smss;
            var status = false;

            try
            {
                smss = (Process.GetProcessesByName("smss")[0]).Id;
            }
            catch
            {
                return status;
            }

            do
            {
                IntPtr hProcess = NativeMethods.OpenProcess(
                    ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                    true,
                    smss);

                if (hProcess == IntPtr.Zero)
                    break;

                status = NativeMethods.OpenProcessToken(
                    hProcess,
                    TokenAccessFlags.TOKEN_DUPLICATE,
                    out IntPtr hToken);
                NativeMethods.CloseHandle(hProcess);

                if (!status)
                    break;

                status = NativeMethods.DuplicateTokenEx(
                    hToken,
                    TokenAccessFlags.MAXIMUM_ALLOWED,
                    IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    TOKEN_TYPE.TokenImpersonation,
                    out IntPtr hDupToken);
                NativeMethods.CloseHandle(hToken);

                if (!status)
                    break;

                EnableMultiplePrivileges(hDupToken, privs);
                status = ImpersonateThreadToken(hDupToken);
                NativeMethods.CloseHandle(hDupToken);
            } while (false);

            return status;
        }


        public static bool ImpersonateThreadToken(IntPtr hImpersonationToken)
        {
            IntPtr pImpersonationLevel = Marshal.AllocHGlobal(4);
            bool status = NativeMethods.ImpersonateLoggedOnUser(hImpersonationToken);

            if (status)
            {
                NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                    WindowsIdentity.GetCurrent().Token,
                    TOKEN_INFORMATION_CLASS.TokenImpersonationLevel,
                    pImpersonationLevel,
                    4u,
                    out uint _);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (status)
                {
                    var level = (SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(pImpersonationLevel);

                    if (level == SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation)
                        status = true;
                    else if (level == SECURITY_IMPERSONATION_LEVEL.SecurityDelegation)
                        status = true;
                    else
                        status = false;
                }
            }

            Marshal.FreeHGlobal(pImpersonationLevel);

            return status;
        }


        public static bool RemoveSinglePrivilege(IntPtr hToken, string privilegeName)
        {
            bool status = NativeMethods.LookupPrivilegeValue(null, privilegeName, out LUID luid);

            if (status)
                status = RemoveSinglePrivilege(hToken, luid);

            return status;
        }


        public static bool RemoveSinglePrivilege(IntPtr hToken, LUID priv)
        {
            int error;
            bool status;
            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES(1);
            tp.Privileges[0].Luid = priv;
            tp.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.REMOVED;
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            status = NativeMethods.AdjustTokenPrivileges(
                hToken,
                false,
                pTokenPrivilege,
                0,
                IntPtr.Zero,
                IntPtr.Zero);
            error = Marshal.GetLastWin32Error();
            status = (status && (error == 0));

            if (!status)
            {
                Console.WriteLine("[-] Failed to remove {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
            }

            return status;
        }


        public static bool SetMandatoryLevel(IntPtr hToken, string mandatoryLevelSid)
        {
            int error;

            if (!NativeMethods.ConvertStringSidToSid(mandatoryLevelSid, out IntPtr pSid))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to resolve integrity level SID.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            var tokenIntegrityLevel = new TOKEN_MANDATORY_LABEL
            {
                Label = new SID_AND_ATTRIBUTES
                {
                    Sid = pSid,
                    Attributes = (uint)(SE_GROUP_ATTRIBUTES.SE_GROUP_INTEGRITY),
                }
            };

            var size = Marshal.SizeOf(tokenIntegrityLevel);
            var pTokenIntegrityLevel = Marshal.AllocHGlobal(size);
            Helpers.ZeroMemory(pTokenIntegrityLevel, size);
            Marshal.StructureToPtr(tokenIntegrityLevel, pTokenIntegrityLevel, true);
            size += NativeMethods.GetLengthSid(pSid);

            Console.WriteLine("[>] Trying to set {0}.",
                Helpers.ConvertStringSidToMandatoryLevelName(mandatoryLevelSid));

            if (!NativeMethods.SetTokenInformation(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                pTokenIntegrityLevel,
                size))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to set integrity level.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                
                return false;
            }

            Console.WriteLine("[+] {0} is set successfully.\n",
                Helpers.ConvertStringSidToMandatoryLevelName(mandatoryLevelSid));

            return true;
        }
    }
}
