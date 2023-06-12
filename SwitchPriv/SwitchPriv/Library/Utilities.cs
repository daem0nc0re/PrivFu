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
        public static bool DisableTokenPrivileges(
            IntPtr hToken,
            List<string> privsToDisabled,
            out Dictionary<string, bool> adjustedPrivs)
        {
            var allDisabled = true;
            adjustedPrivs = new Dictionary<string, bool>();

            do
            {
                if (privsToDisabled.Count == 0)
                    break;

                allDisabled = Helpers.GetTokenPrivileges(
                    hToken,
                    out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                if (!allDisabled)
                    break;

                foreach (var priv in privsToDisabled)
                {
                    adjustedPrivs.Add(priv, true);

                    foreach (var available in availablePrivs)
                    {
                        if (Helpers.CompareIgnoreCase(available.Key, priv))
                        {
                            if ((available.Value & SE_PRIVILEGE_ATTRIBUTES.ENABLED) == 0)
                            {
                                adjustedPrivs[priv] = false;
                            }
                            else
                            {
                                var tokenPrivileges = new TOKEN_PRIVILEGES(1);

                                if (NativeMethods.LookupPrivilegeValue(
                                    null,
                                    priv,
                                    out tokenPrivileges.Privileges[0].Luid))
                                {
                                    adjustedPrivs[priv] = NativeMethods.AdjustTokenPrivileges(
                                        hToken,
                                        false,
                                        in tokenPrivileges,
                                        20,
                                        out TOKEN_PRIVILEGES _,
                                        out int _);
                                    adjustedPrivs[priv] = !(adjustedPrivs[priv] && (Marshal.GetLastWin32Error() == 0));
                                }
                            }

                            break;
                        }
                    }

                    if (adjustedPrivs[priv])
                        allDisabled = false;
                }
            } while (false);

            return allDisabled;
        }


        public static bool EnableTokenPrivileges(
            List<string> requiredPrivs,
            out Dictionary<string, bool> adjustedPrivs)
        {
            return EnableTokenPrivileges(
                WindowsIdentity.GetCurrent().Token,
                requiredPrivs,
                out adjustedPrivs);
        }


        public static bool EnableTokenPrivileges(
            IntPtr hToken,
            List<string> requiredPrivs,
            out Dictionary<string, bool> adjustedPrivs)
        {
            var allEnabled = true;
            adjustedPrivs = new Dictionary<string, bool>();

            do
            {
                if (requiredPrivs.Count == 0)
                    break;

                allEnabled = Helpers.GetTokenPrivileges(
                    hToken,
                    out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                if (!allEnabled)
                    break;

                foreach (var priv in requiredPrivs)
                {
                    adjustedPrivs.Add(priv, false);

                    foreach (var available in availablePrivs)
                    {
                        if (Helpers.CompareIgnoreCase(available.Key, priv))
                        {
                            if ((available.Value & SE_PRIVILEGE_ATTRIBUTES.ENABLED) != 0)
                            {
                                adjustedPrivs[priv] = true;
                            }
                            else
                            {
                                var tokenPrivileges = new TOKEN_PRIVILEGES(1);

                                if (NativeMethods.LookupPrivilegeValue(
                                    null,
                                    priv,
                                    out tokenPrivileges.Privileges[0].Luid))
                                {
                                    tokenPrivileges.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.ENABLED;
                                    adjustedPrivs[priv] = NativeMethods.AdjustTokenPrivileges(
                                        hToken,
                                        false,
                                        in tokenPrivileges,
                                        20,
                                        out TOKEN_PRIVILEGES _,
                                        out int _);
                                    adjustedPrivs[priv] = (adjustedPrivs[priv] && (Marshal.GetLastWin32Error() == 0));
                                }
                            }

                            break;
                        }
                    }

                    if (!adjustedPrivs[priv])
                        allEnabled = false;
                }
            } while (false);

            return allEnabled;
        }


        public static bool ImpersonateAsSmss()
        {
            return ImpersonateAsSmss(new List<string> { });
        }


        public static bool ImpersonateAsSmss(List<string> privs)
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

                EnableTokenPrivileges(hDupToken, privs, out Dictionary<string, bool> _);
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
