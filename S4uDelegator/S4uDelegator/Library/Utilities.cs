using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using S4uDelegator.Interop;

namespace S4uDelegator.Library
{
    class Utilities
    {
        public static bool CreateTokenAssignedProcess(
            IntPtr hToken,
            string command)
        {
            int error;
            var startupInfo = new Win32Struct.STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(startupInfo);
            startupInfo.lpDesktop = "Winsta0\\Default";

            Console.WriteLine("[>] Trying to create a token assigned process.\n");

            bool status = Win32Api.CreateProcessAsUser(
                hToken,
                null,
                command,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                0,
                IntPtr.Zero,
                Environment.CurrentDirectory,
                ref startupInfo,
                out Win32Struct.PROCESS_INFORMATION processInformation);

            if (!status)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to create new process.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            Win32Api.WaitForSingleObject(processInformation.hProcess, uint.MaxValue);
            Win32Api.CloseHandle(processInformation.hThread);
            Win32Api.CloseHandle(processInformation.hProcess);

            return true;
        }


        public static void EnableAllPrivileges(IntPtr hToken)
        {
            Dictionary<Win32Struct.LUID, uint> privs = GetAvailablePrivileges(hToken);
            bool isEnabled;

            foreach (var priv in privs)
            {
                isEnabled = ((priv.Value & (uint)Win32Const.SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED) != 0);

                if (!isEnabled)
                {
                    EnableSinglePrivilege(hToken, priv.Key);
                }
            }
        }


        public static bool EnableSinglePrivilege(IntPtr hToken, Win32Struct.LUID priv)
        {
            int error;
            var tp = new Win32Struct.TOKEN_PRIVILEGES(1);
            tp.Privileges[0].Luid = priv;
            tp.Privileges[0].Attributes = (uint)Win32Const.SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED;

            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(tp));
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            if (!Win32Api.AdjustTokenPrivileges(
                hToken,
                false,
                pTokenPrivilege,
                0,
                IntPtr.Zero,
                IntPtr.Zero))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to enable {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            error = Marshal.GetLastWin32Error();

            if (error != 0)
            {
                Console.WriteLine("[-] Failed to enable {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            Console.WriteLine("[+] {0} is enabled successfully.", Helpers.GetPrivilegeName(priv));

            return true;
        }


        public static bool EnableMultiplePrivileges(
            IntPtr hToken,
            string[] privs)
        {
            StringComparison opt = StringComparison.OrdinalIgnoreCase;
            Dictionary<string, bool> results = new Dictionary<string, bool>();
            var privList = new List<string>(privs);
            var availablePrivs = GetAvailablePrivileges(hToken);
            bool isEnabled;
            bool enabledAll = true;

            foreach (var name in privList)
            {
                results.Add(name, false);
            }

            foreach (var priv in availablePrivs)
            {
                foreach (var name in privList)
                {
                    if (string.Compare(Helpers.GetPrivilegeName(priv.Key), name, opt) == 0)
                    {
                        isEnabled = ((priv.Value & (uint)Win32Const.SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED) != 0);

                        if (isEnabled)
                        {
                            results[name] = true;
                        }
                        else
                        {
                            results[name] = EnableSinglePrivilege(hToken, priv.Key);
                        }
                    }
                }
            }

            foreach (var result in results)
            {
                if (!result.Value)
                {
                    Console.WriteLine(
                        "[-] {0} is not available.",
                        result.Key);

                    enabledAll = false;
                }
            }

            return enabledAll;
        }


        public static Dictionary<Win32Struct.LUID, uint> GetAvailablePrivileges(
            IntPtr hToken)
        {
            int error;
            bool status;
            int bufferLength = Marshal.SizeOf(typeof(Win32Struct.TOKEN_PRIVILEGES));
            var availablePrivs = new Dictionary<Win32Struct.LUID, uint>();
            IntPtr pTokenPrivileges;

            do
            {
                pTokenPrivileges = Marshal.AllocHGlobal(bufferLength);
                Helpers.ZeroMemory(pTokenPrivileges, bufferLength);

                status = Win32Api.GetTokenInformation(
                    hToken,
                    Win32Const.TOKEN_INFORMATION_CLASS.TokenPrivileges,
                    pTokenPrivileges,
                    bufferLength,
                    out bufferLength);
                error = Marshal.GetLastWin32Error();

                if (!status)
                    Marshal.FreeHGlobal(pTokenPrivileges);
            } while (!status && (error == Win32Const.ERROR_INSUFFICIENT_BUFFER));

            if (!status)
                return availablePrivs;

            int privCount = Marshal.ReadInt32(pTokenPrivileges);
            IntPtr buffer = new IntPtr(pTokenPrivileges.ToInt64() + Marshal.SizeOf(privCount));

            for (var count = 0; count < privCount; count++)
            {
                var luidAndAttr = (Win32Struct.LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                    buffer,
                    typeof(Win32Struct.LUID_AND_ATTRIBUTES));

                availablePrivs.Add(luidAndAttr.Luid, luidAndAttr.Attributes);
                buffer = new IntPtr(buffer.ToInt64() + Marshal.SizeOf(luidAndAttr));
            }

            Marshal.FreeHGlobal(pTokenPrivileges);

            return availablePrivs;
        }


        public static IntPtr GetKerbS4uLogonToken(
            string upn,
            string realm,
            Win32Const.SECURITY_LOGON_TYPE type,
            string[] groupSids)
        {
            int error;
            int ntstatus;
            var pkgName = new Win32Struct.LSA_STRING(Win32Const.NEGOSSP_NAME_A);
            var tokenSource = new Win32Struct.TOKEN_SOURCE("NtLmSsp");
            var pTokenGroups = IntPtr.Zero;

            Console.WriteLine("[>] Trying to Kerberos S4U logon.");

            ntstatus = Win32Api.LsaConnectUntrusted(out IntPtr hLsa);

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                error = Win32Api.LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to connect LSA store.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            ntstatus = Win32Api.LsaLookupAuthenticationPackage(
                hLsa,
                ref pkgName,
                out uint authnPkg);

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                error = Win32Api.LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to lookup auth package.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.LsaClose(hLsa);

                return IntPtr.Zero;
            }

            var kerbS4uLogon = new Win32Struct.KERB_S4U_LOGON(upn, realm);
            var originName = new Win32Struct.LSA_STRING("S4U");
            var pS4uTokenBuffer = Marshal.AllocHGlobal(IntPtr.Size);

            if (groupSids.Length > 0)
            {
                var tokenGroups = new Win32Struct.TOKEN_GROUPS(0);
                pTokenGroups = Marshal.AllocHGlobal(Marshal.SizeOf(tokenGroups));

                for (var idx = 0; idx < groupSids.Length; idx++)
                {
                    if (!Win32Api.ConvertStringSidToSid(
                        groupSids[idx],
                        out IntPtr pSid))
                    {
                        continue;
                    }

                    tokenGroups.Groups[idx].Sid = pSid;
                    tokenGroups.Groups[idx].Attributes = (uint)(
                        Win32Const.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                        Win32Const.SE_GROUP_ATTRIBUTES.SE_GROUP_MANDATORY);
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

            ntstatus = Win32Api.LsaLogonUser(
                hLsa,
                ref originName,
                type,
                authnPkg,
                kerbS4uLogon.Pointer(),
                kerbS4uLogon.Length(),
                pTokenGroups,
                ref tokenSource,
                out IntPtr profileBuffer,
                out int profileBufferLength,
                out Win32Struct.LUID logonId,
                pS4uTokenBuffer,
                out Win32Struct.QUOTA_LIMITS quotas,
                out int subStatus);

            kerbS4uLogon.Dispose();
            Win32Api.LsaFreeReturnBuffer(profileBuffer);
            Win32Api.LsaClose(hLsa);

            if (pTokenGroups != IntPtr.Zero)
                Marshal.FreeHGlobal(pTokenGroups);

            var hS4uToken = Marshal.ReadIntPtr(pS4uTokenBuffer);
            Marshal.FreeHGlobal(pS4uTokenBuffer);

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                error = Win32Api.LsaNtStatusToWinError(ntstatus);
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
            Win32Const.SECURITY_LOGON_TYPE type,
            string[] groupSids)
        {
            int error;
            int ntstatus;
            var pkgName = new Win32Struct.LSA_STRING(Win32Const.MSV1_0_PACKAGE_NAME);
            var tokenSource = new Win32Struct.TOKEN_SOURCE("User32");
            var pTokenGroups = IntPtr.Zero;

            Console.WriteLine("[>] Trying to MSV S4U logon.");

            ntstatus = Win32Api.LsaConnectUntrusted(out IntPtr hLsa);

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                error = Win32Api.LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to connect lsa store.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            ntstatus = Win32Api.LsaLookupAuthenticationPackage(
                hLsa,
                ref pkgName,
                out uint authnPkg);

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                error = Win32Api.LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to lookup auth package.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.LsaClose(hLsa);

                return IntPtr.Zero;
            }

            var msvS4uLogon = new Win32Struct.MSV1_0_S4U_LOGON(username, domain);
            var originName = new Win32Struct.LSA_STRING("S4U");
            var pS4uTokenBuffer = Marshal.AllocHGlobal(IntPtr.Size);

            if (groupSids.Length > 0)
            {
                var tokenGroups = new Win32Struct.TOKEN_GROUPS(0);
                pTokenGroups = Marshal.AllocHGlobal(Marshal.SizeOf(tokenGroups));

                for (var idx = 0; idx < groupSids.Length; idx++)
                {
                    if (!Win32Api.ConvertStringSidToSid(
                        groupSids[idx],
                        out IntPtr pSid))
                    {
                        continue;
                    }

                    tokenGroups.Groups[idx].Sid = pSid;
                    tokenGroups.Groups[idx].Attributes = (uint)(
                        Win32Const.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                        Win32Const.SE_GROUP_ATTRIBUTES.SE_GROUP_MANDATORY);
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

            ntstatus = Win32Api.LsaLogonUser(
                hLsa,
                ref originName,
                type,
                authnPkg,
                msvS4uLogon.Pointer(),
                msvS4uLogon.Length(),
                pTokenGroups,
                ref tokenSource,
                out IntPtr profileBuffer,
                out int profileBufferLength,
                out Win32Struct.LUID logonId,
                pS4uTokenBuffer,
                out Win32Struct.QUOTA_LIMITS quotas,
                out int subStatus);

            msvS4uLogon.Dispose();
            Win32Api.LsaFreeReturnBuffer(profileBuffer);
            Win32Api.LsaClose(hLsa);

            if (pTokenGroups != IntPtr.Zero)
                Marshal.FreeHGlobal(pTokenGroups);

            var hS4uToken = Marshal.ReadIntPtr(pS4uTokenBuffer);
            Marshal.FreeHGlobal(pS4uTokenBuffer);

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                error = Win32Api.LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to S4U logon.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, true));

                return IntPtr.Zero;
            }

            Console.WriteLine("[+] S4U logon is successful.");

            return hS4uToken;
        }


        public static bool ImpersonateAsSmss(string[] privs)
        {
            int error;
            int smss;

            Console.WriteLine("[>] Trying to impersonate as smss.exe.");

            try
            {
                smss = (Process.GetProcessesByName("smss")[0]).Id;
            }
            catch
            {
                Console.WriteLine("[-] Failed to get process id of smss.exe.\n");

                return false;
            }

            IntPtr hProcess = Win32Api.OpenProcess(
                Win32Const.ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                true,
                smss);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get handle to smss.exe process.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            if (!Win32Api.OpenProcessToken(
                hProcess,
                Win32Const.TokenAccessFlags.TOKEN_DUPLICATE,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get handle to smss.exe process token.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hProcess);

                return false;
            }

            Win32Api.CloseHandle(hProcess);

            if (!Win32Api.DuplicateTokenEx(
                hToken,
                Win32Const.TokenAccessFlags.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                Win32Const.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                Win32Const.TOKEN_TYPE.TokenPrimary,
                out IntPtr hDupToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to duplicate smss.exe process token.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.CloseHandle(hToken);

                return false;
            }

            if (!EnableMultiplePrivileges(hDupToken, privs))
            {
                Win32Api.CloseHandle(hDupToken);
                Win32Api.CloseHandle(hToken);

                return false;
            }

            if (!ImpersonateThreadToken(hDupToken))
            {
                Win32Api.CloseHandle(hDupToken);
                Win32Api.CloseHandle(hToken);

                return false;
            }

            Win32Api.CloseHandle(hDupToken);
            Win32Api.CloseHandle(hToken);

            return true;
        }


        public static bool ImpersonateThreadToken(IntPtr hImpersonationToken)
        {
            int error;

            Console.WriteLine("[>] Trying to impersonate thread token.");
            Console.WriteLine("    |-> Current Thread ID : {0}", Win32Api.GetCurrentThreadId());

            if (!Win32Api.ImpersonateLoggedOnUser(hImpersonationToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to impersonation.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            IntPtr pImpersonationLevel = Helpers.GetInformationFromToken(
                hCurrentToken,
                Win32Const.TOKEN_INFORMATION_CLASS.TokenImpersonationLevel);
            var impersonationLevel = (Win32Const.SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(
                pImpersonationLevel);
            Win32Api.LocalFree(pImpersonationLevel);

            if (impersonationLevel ==
                Win32Const.SECURITY_IMPERSONATION_LEVEL.SecurityIdentification)
            {
                Console.WriteLine("[-] Failed to impersonation.");
                Console.WriteLine("    |-> May not have {0}.\n", Win32Const.SE_IMPERSONATE_NAME);

                return false;
            }
            else
            {
                Console.WriteLine("[+] Impersonation is successful.");

                return true;
            }
        }

    }
}
