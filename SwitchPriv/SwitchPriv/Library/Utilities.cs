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
                            if ((available.Value & SE_PRIVILEGE_ATTRIBUTES.Enabled) == 0)
                            {
                                adjustedPrivs[priv] = false;
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
                                    tokenPrivileges.Privileges[0].Attributes = 0;
                                    Marshal.StructureToPtr(tokenPrivileges, pTokenPrivileges, true);

                                    adjustedPrivs[priv] = NativeMethods.AdjustTokenPrivileges(
                                        hToken,
                                        false,
                                        pTokenPrivileges,
                                        Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)),
                                        IntPtr.Zero,
                                        out int _);
                                    adjustedPrivs[priv] = !(adjustedPrivs[priv] && (Marshal.GetLastWin32Error() == 0));
                                }

                                Marshal.FreeHGlobal(pTokenPrivileges);
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
                            if ((available.Value & SE_PRIVILEGE_ATTRIBUTES.Enabled) != 0)
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
                                    tokenPrivileges.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.Enabled;
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
                    SECURITY_IMPERSONATION_LEVEL.Impersonation,
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
                    var level = Marshal.ReadInt32(pImpersonationLevel);
                    status = (level >= (int)SECURITY_IMPERSONATION_LEVEL.Impersonation);
                }
            }

            Marshal.FreeHGlobal(pImpersonationLevel);

            return status;
        }


        public static bool RemoveTokenPrivileges(
            IntPtr hToken,
            List<string> requiredPrivs,
            out Dictionary<string, bool> operationStatus)
        {
            var allRemoved = true;
            operationStatus = new Dictionary<string, bool>();

            do
            {
                if (requiredPrivs.Count == 0)
                    break;

                allRemoved = Helpers.GetTokenPrivileges(
                    hToken,
                    out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                if (!allRemoved)
                    break;

                foreach (var priv in requiredPrivs)
                {
                    operationStatus.Add(priv, true);

                    foreach (var available in availablePrivs)
                    {
                        if (Helpers.CompareIgnoreCase(available.Key, priv))
                        {
                            IntPtr pTokenPrivileges = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));
                            var tokenPrivileges = new TOKEN_PRIVILEGES(1);

                            if (NativeMethods.LookupPrivilegeValue(
                                null,
                                priv,
                                out tokenPrivileges.Privileges[0].Luid))
                            {
                                tokenPrivileges.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.Removed;
                                Marshal.StructureToPtr(tokenPrivileges, pTokenPrivileges, true);

                                operationStatus[priv] = NativeMethods.AdjustTokenPrivileges(
                                    hToken,
                                    false,
                                    pTokenPrivileges,
                                    Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)),
                                    IntPtr.Zero,
                                    out int _);
                                operationStatus[priv] = (operationStatus[priv] && (Marshal.GetLastWin32Error() == 0));
                            }

                            Marshal.FreeHGlobal(pTokenPrivileges);
                            break;
                        }
                    }

                    if (!operationStatus[priv])
                        allRemoved = false;
                }
            } while (false);

            return allRemoved;
        }


        public static int ResolveProcessId(int pid, out string processName)
        {
            processName = null;

            if (pid == -1)
                pid = Helpers.GetParentProcessId();

            if (pid != -1)
            {
                try
                {
                    processName = Process.GetProcessById(pid).ProcessName;
                }
                catch
                {
                    pid = -1;
                    processName = null;
                }
            }

            return pid;
        }


        public static bool SetMandatoryLevel(IntPtr hToken, string mandatoryLevelSid)
        {
            var status = false;

            if (NativeMethods.ConvertStringSidToSid(mandatoryLevelSid, out IntPtr pSid))
            {
                NTSTATUS ntstatus;
                int nBufferSize = Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL));
                IntPtr pTokenIntegrityLevel = Marshal.AllocHGlobal(nBufferSize);
                var tokenIntegrityLevel = new TOKEN_MANDATORY_LABEL
                {
                    Label = new SID_AND_ATTRIBUTES
                    {
                        Sid = pSid,
                        Attributes = (uint)(SE_GROUP_ATTRIBUTES.Integrity),
                    }
                };
                Marshal.StructureToPtr(tokenIntegrityLevel, pTokenIntegrityLevel, true);
                nBufferSize += NativeMethods.GetLengthSid(pSid);

                ntstatus = NativeMethods.NtSetInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                    pTokenIntegrityLevel,
                    (uint)nBufferSize);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);
                Marshal.FreeHGlobal(pTokenIntegrityLevel);
            }

            return status;
        }
    }
}
