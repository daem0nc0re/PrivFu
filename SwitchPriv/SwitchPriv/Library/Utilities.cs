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
                    out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                if (!allDisabled)
                    break;

                foreach (var priv in privsToDisabled)
                {
                    adjustedPrivs.Add(priv, true);

                    foreach (var available in availablePrivs)
                    {
                        if (Helpers.CompareIgnoreCase(available.Key.ToString(), priv))
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
            List<SE_PRIVILEGE_ID> requiredPrivs,
            out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs)
        {
            return EnableTokenPrivileges(
                WindowsIdentity.GetCurrent().Token,
                requiredPrivs,
                out adjustedPrivs);
        }


        public static bool EnableTokenPrivileges(
            IntPtr hToken,
            in List<SE_PRIVILEGE_ID> requiredPrivs,
            out Dictionary<SE_PRIVILEGE_ID, bool> privStates)
        {
            NTSTATUS ntstatus;
            var nOffset = Marshal.OffsetOf(typeof(TOKEN_PRIVILEGES), "Privileges").ToInt32();
            var nInfoLength = (uint)(nOffset + Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES)) * 36);
            var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            var bAllEnabled = true;
            privStates = new Dictionary<SE_PRIVILEGE_ID, bool>();

            foreach (var id in requiredPrivs)
                privStates.Add(id, false);

            do
            {
                int nPrivilegeCount;
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenPrivileges,
                    pInfoBuffer,
                    nInfoLength,
                    out uint _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                nPrivilegeCount = Marshal.ReadInt32(pInfoBuffer);

                for (var idx = 0; idx < nPrivilegeCount; idx++)
                {
                    var priv = Marshal.ReadInt64(pInfoBuffer, nOffset);
                    var attr = Marshal.ReadInt32(pInfoBuffer, nOffset + 8);

                    foreach (var id in requiredPrivs)
                    {
                        bool bEnabled = false;

                        if (priv == (long)id)
                        {
                            bEnabled = (((int)SE_PRIVILEGE_ATTRIBUTES.Enabled & attr) != 0);

                            if (!bEnabled)
                            {
                                var info = new TOKEN_PRIVILEGES
                                {
                                    PrivilegeCount = 1,
                                    Privileges = new LUID_AND_ATTRIBUTES[1]
                                };
                                info.Privileges[0].Luid.QuadPart = (long)id;
                                info.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.Enabled;
                                Marshal.StructureToPtr(info, pInfoBuffer, true);

                                ntstatus = NativeMethods.NtAdjustPrivilegesToken(
                                    hToken,
                                    BOOLEAN.FALSE,
                                    pInfoBuffer,
                                    (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)),
                                    IntPtr.Zero,
                                    out uint _);
                                bEnabled = (ntstatus == Win32Consts.STATUS_SUCCESS);
                            }

                            if (bEnabled)
                                privStates[id] = true;
                        }
                    }

                    nOffset += Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
                }
            } while (false);

            Marshal.FreeHGlobal(pInfoBuffer);

            foreach (var status in privStates.Values)
            {
                if (!status)
                {
                    NativeMethods.RtlSetLastWin32Error(Win32Consts.ERROR_PRIVILEGE_NOT_HELD);
                    bAllEnabled = false;
                    break;
                }
            }

            return bAllEnabled;
        }


        public static bool ImpersonateAsSmss()
        {
            return ImpersonateAsSmss(new List<SE_PRIVILEGE_ID> { });
        }


        public static bool ImpersonateAsSmss(List<SE_PRIVILEGE_ID> privs)
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
                NativeMethods.NtClose(hProcess);

                if (!status)
                    break;

                status = NativeMethods.DuplicateTokenEx(
                    hToken,
                    TokenAccessFlags.MAXIMUM_ALLOWED,
                    IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.Impersonation,
                    TOKEN_TYPE.TokenImpersonation,
                    out IntPtr hDupToken);
                NativeMethods.NtClose(hToken);

                if (!status)
                    break;

                EnableTokenPrivileges(hDupToken, privs, out Dictionary<SE_PRIVILEGE_ID, bool> _);
                status = ImpersonateThreadToken(hDupToken);
                NativeMethods.NtClose(hDupToken);
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
                    out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                if (!allRemoved)
                    break;

                foreach (var priv in requiredPrivs)
                {
                    operationStatus.Add(priv, true);

                    foreach (var available in availablePrivs)
                    {
                        if (Helpers.CompareIgnoreCase(available.Key.ToString(), priv))
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


        public static IntPtr OpenProcessToken(int pid, ACCESS_MASK tokenAccessMask)
        {
            int nDosErrorCode;
            var hToken = IntPtr.Zero;
            var objectAttrbutes = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
            };
            var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(pid) };
            NTSTATUS ntstatus = NativeMethods.NtOpenProcess(
                out IntPtr hProcess,
                ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                in objectAttrbutes,
                in clientId);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                ntstatus = NativeMethods.NtOpenProcessToken(
                    hProcess,
                    tokenAccessMask,
                    out hToken);
                NativeMethods.NtClose(hProcess);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    hToken = IntPtr.Zero;
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return hToken;
        }


        public static int ResolveProcessId(int pid, out string processName)
        {
            processName = null;

            if (pid == -1)
            {
                pid = Helpers.GetParentProcessId();
            }
            else
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
                nBufferSize += 8 + (4 * Marshal.ReadByte(pSid, 1)); // SID Length

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
