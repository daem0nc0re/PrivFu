using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using S4uDelegator.Interop;

namespace S4uDelegator.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static bool CreateTokenAssignedProcess(
            IntPtr hToken,
            string command)
        {
            var startupInfo = new STARTUPINFO
            {
                cb = Marshal.SizeOf(typeof(STARTUPINFO)),
                lpDesktop = @"Winsta0\Default"
            };
            bool status = NativeMethods.CreateProcessAsUser(
                hToken,
                null,
                command,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                0,
                IntPtr.Zero,
                Environment.CurrentDirectory,
                in startupInfo,
                out PROCESS_INFORMATION processInformation);

            if (status)
            {
                NativeMethods.WaitForSingleObject(processInformation.hProcess, uint.MaxValue);
                NativeMethods.NtClose(processInformation.hThread);
                NativeMethods.NtClose(processInformation.hProcess);
            }

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


        public static bool ImpersonateWithS4uLogon(
            string upn,
            string domain,
            in LSA_STRING pkgName,
            in TOKEN_SOURCE tokenSource,
            List<string> localGroupSids)
        {
            var status = false;

            do
            {
                IntPtr pTokenGroups;
                int nGroupCount = localGroupSids.Count;
                var nGroupsOffset = Marshal.OffsetOf(typeof(TOKEN_GROUPS), "Groups").ToInt32();
                var nTokenGroupsSize = nGroupsOffset;
                var pSidBuffersToLocalFree = new List<IntPtr>();
                nTokenGroupsSize += (Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES)) * nGroupCount);

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

                if (nGroupCount > 0)
                {
                    int nUnitSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
                    var attributes = (int)(SE_GROUP_ATTRIBUTES.MANDATORY | SE_GROUP_ATTRIBUTES.ENABLED);
                    pTokenGroups = Marshal.AllocHGlobal(nTokenGroupsSize);
                    nGroupCount = 0;
                    Helpers.ZeroMemory(pTokenGroups, nTokenGroupsSize);

                    foreach (var stringSid in localGroupSids)
                    {
                        if (NativeMethods.ConvertStringSidToSid(stringSid, out IntPtr pSid))
                        {
                            Helpers.ConvertSidToAccountName(pSid, out string _, out string _, out SID_NAME_USE sidType);

                            if ((sidType == SID_NAME_USE.Alias) ||
                                (sidType == SID_NAME_USE.WellKnownGroup))
                            {
                                Marshal.WriteIntPtr(pTokenGroups, (nGroupsOffset + (nGroupCount * nUnitSize)), pSid);
                                Marshal.WriteInt32(pTokenGroups, (nGroupsOffset + (nGroupCount * nUnitSize) + IntPtr.Size), attributes);
                                pSidBuffersToLocalFree.Add(pSid);
                                nGroupCount++;
                            }
                        }
                    }

                    if (nGroupCount == 0)
                    {
                        Marshal.FreeHGlobal(pTokenGroups);
                        pTokenGroups = IntPtr.Zero;
                    }
                    else
                    {
                        Marshal.WriteInt32(pTokenGroups, nGroupCount);
                    }
                }
                else
                {
                    pTokenGroups = IntPtr.Zero;
                }

                using (var msv = new MSV1_0_S4U_LOGON(MSV1_0_LOGON_SUBMIT_TYPE.MsV1_0S4ULogon, 0, upn, domain))
                {
                    IntPtr pTokenBuffer = Marshal.AllocHGlobal(IntPtr.Size);
                    var originName = new LSA_STRING("S4U");
                    ntstatus = NativeMethods.LsaLogonUser(
                        hLsa,
                        in originName,
                        SECURITY_LOGON_TYPE.Network,
                        authnPkg,
                        msv.Buffer,
                        (uint)msv.Length,
                        pTokenGroups,
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

                if (pTokenGroups != IntPtr.Zero)
                    Marshal.FreeHGlobal(pTokenGroups);

                foreach (var pSidBuffer in pSidBuffersToLocalFree)
                    NativeMethods.LocalFree(pSidBuffer);
            } while (false);

            return status;
        }


        public static IntPtr GetKerbS4uLogonToken(
            string upn,
            string realm,
            SECURITY_LOGON_TYPE type,
            string[] groupSids)
        {
            int error;
            NTSTATUS ntstatus;
            var pkgName = new LSA_STRING(Win32Consts.NEGOSSP_NAME_A);
            var tokenSource = new TOKEN_SOURCE("NtLmSsp");
            var pTokenGroups = IntPtr.Zero;

            Console.WriteLine("[>] Trying to Kerberos S4U logon.");

            ntstatus = NativeMethods.LsaConnectUntrusted(out IntPtr hLsa);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                error = NativeMethods.LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to connect LSA store.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            ntstatus = NativeMethods.LsaLookupAuthenticationPackage(
                hLsa,
                in pkgName,
                out uint authnPkg);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                error = NativeMethods.LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to lookup auth package.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                NativeMethods.LsaClose(hLsa);

                return IntPtr.Zero;
            }

            var kerbS4uLogon = new MSV1_0_S4U_LOGON(
                MSV1_0_LOGON_SUBMIT_TYPE.MsV1_0S4ULogon,
                0,
                upn,
                realm);
            var originName = new LSA_STRING("S4U");
            var pS4uTokenBuffer = Marshal.AllocHGlobal(IntPtr.Size);

            if (groupSids.Length > 0)
            {
                var tokenGroups = new TOKEN_GROUPS(0);
                pTokenGroups = Marshal.AllocHGlobal(Marshal.SizeOf(tokenGroups));

                for (var idx = 0; idx < groupSids.Length; idx++)
                {
                    if (!NativeMethods.ConvertStringSidToSid(
                        groupSids[idx],
                        out IntPtr pSid))
                    {
                        continue;
                    }

                    tokenGroups.Groups[idx].Sid = pSid;
                    tokenGroups.Groups[idx].Attributes = (uint)(
                        SE_GROUP_ATTRIBUTES.ENABLED |
                        SE_GROUP_ATTRIBUTES.MANDATORY);
                    tokenGroups.GroupCount++;
                }

                if (tokenGroups.GroupCount == 0)
                {
                    Marshal.FreeHGlobal(pTokenGroups);
                    pTokenGroups = IntPtr.Zero;
                }
                else
                {
                    Marshal.StructureToPtr(tokenGroups, pTokenGroups, true);
                }
            }

            ntstatus = NativeMethods.LsaLogonUser(
                hLsa,
                in originName,
                type,
                authnPkg,
                kerbS4uLogon.Buffer,
                (uint)kerbS4uLogon.Length,
                pTokenGroups,
                in tokenSource,
                out IntPtr profileBuffer,
                out uint _,
                out LUID _,
                pS4uTokenBuffer,
                out QUOTA_LIMITS _,
                out int _);

            kerbS4uLogon.Dispose();
            NativeMethods.LsaFreeReturnBuffer(profileBuffer);
            NativeMethods.LsaClose(hLsa);

            if (pTokenGroups != IntPtr.Zero)
                Marshal.FreeHGlobal(pTokenGroups);

            var hS4uToken = Marshal.ReadIntPtr(pS4uTokenBuffer);
            Marshal.FreeHGlobal(pS4uTokenBuffer);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                error = NativeMethods.LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to S4U logon.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, true));

                return IntPtr.Zero;
            }

            Console.WriteLine("[+] S4U logon is successful.");

            return hS4uToken;
        }


        public static IntPtr GetMsvS4uLogonToken(
            string username,
            string domain,
            SECURITY_LOGON_TYPE type,
            string[] groupSids)
        {
            int error;
            NTSTATUS ntstatus;
            var pkgName = new LSA_STRING(Win32Consts.MSV1_0_PACKAGE_NAME);
            var tokenSource = new TOKEN_SOURCE("User32");
            var pTokenGroups = IntPtr.Zero;

            Console.WriteLine("[>] Trying to MSV S4U logon.");

            ntstatus = NativeMethods.LsaConnectUntrusted(out IntPtr hLsa);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                error = NativeMethods.LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to connect lsa store.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            ntstatus = NativeMethods.LsaLookupAuthenticationPackage(
                hLsa,
                in pkgName,
                out uint authnPkg);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                error = NativeMethods.LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to lookup auth package.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                NativeMethods.LsaClose(hLsa);

                return IntPtr.Zero;
            }

            var msvS4uLogon = new MSV1_0_S4U_LOGON(
                MSV1_0_LOGON_SUBMIT_TYPE.MsV1_0S4ULogon,
                0,
                username,
                domain);
            var originName = new LSA_STRING("S4U");
            var pS4uTokenBuffer = Marshal.AllocHGlobal(IntPtr.Size);

            if (groupSids.Length > 0)
            {
                var tokenGroups = new TOKEN_GROUPS(0);
                pTokenGroups = Marshal.AllocHGlobal(Marshal.SizeOf(tokenGroups));

                for (var idx = 0; idx < groupSids.Length; idx++)
                {
                    if (!NativeMethods.ConvertStringSidToSid(
                        groupSids[idx],
                        out IntPtr pSid))
                    {
                        continue;
                    }

                    tokenGroups.Groups[idx].Sid = pSid;
                    tokenGroups.Groups[idx].Attributes = (uint)(
                        SE_GROUP_ATTRIBUTES.ENABLED |
                        SE_GROUP_ATTRIBUTES.MANDATORY);
                    tokenGroups.GroupCount++;
                }

                if (tokenGroups.GroupCount == 0)
                {
                    Marshal.FreeHGlobal(pTokenGroups);
                    pTokenGroups = IntPtr.Zero;
                }
                else
                {
                    Marshal.StructureToPtr(tokenGroups, pTokenGroups, true);
                }
            }

            ntstatus = NativeMethods.LsaLogonUser(
                hLsa,
                in originName,
                type,
                authnPkg,
                msvS4uLogon.Buffer,
                (uint)msvS4uLogon.Length,
                pTokenGroups,
                in tokenSource,
                out IntPtr profileBuffer,
                out uint _,
                out LUID _,
                pS4uTokenBuffer,
                out QUOTA_LIMITS _,
                out int _);

            msvS4uLogon.Dispose();
            NativeMethods.LsaFreeReturnBuffer(profileBuffer);
            NativeMethods.LsaClose(hLsa);

            if (pTokenGroups != IntPtr.Zero)
                Marshal.FreeHGlobal(pTokenGroups);

            var hS4uToken = Marshal.ReadIntPtr(pS4uTokenBuffer);
            Marshal.FreeHGlobal(pS4uTokenBuffer);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                error = NativeMethods.LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to S4U logon.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, true));

                return IntPtr.Zero;
            }

            Console.WriteLine("[+] S4U logon is successful.");

            return hS4uToken;
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

                EnableTokenPrivileges(hDupToken, privs, out Dictionary<string, bool> _);
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
    }
}
