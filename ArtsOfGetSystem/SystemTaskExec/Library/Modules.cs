using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using SystemTaskExec.Interop;

namespace SystemTaskExec.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool CreateDesktopProcess(string command)
        {
            NTSTATUS ntstatus;
            bool bSuccess;
            var nSessionId = Helpers.GetGuiSessionId();

            if (nSessionId == -1)
            {
                Console.WriteLine("[-] Failed to get the GUI session ID (Error = 0x{0}).",
                    Marshal.GetLastWin32Error().ToString("X8"));
                return false;
            }
            else
            {
                Console.WriteLine("[*] The GUI session ID is {0}.", nSessionId);
            }

            ntstatus = NativeMethods.NtOpenProcessToken(
                new IntPtr(-1),
                ACCESS_MASK.TokenAdjustPrivileges | ACCESS_MASK.TokenDuplicate | ACCESS_MASK.TokenQuery,
                out IntPtr hToken);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to open the current process token (Error = 0x{0}).",
                    ntstatus.ToString("X8"));
                return false;
            }

            do
            {
                var privs = new Dictionary<SE_PRIVILEGE_ID, bool>
                {
                    { SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege, true },
                    { SE_PRIVILEGE_ID.SeIncreaseQuotaPrivilege, true },
                    { SE_PRIVILEGE_ID.SeTcbPrivilege, true }
                };
                var objectAttributes = new OBJECT_ATTRIBUTES
                {
                    Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
                };
                var startupInfo = new STARTUPINFO
                {
                    cb = Marshal.SizeOf(typeof(STARTUPINFO)),
                    wShowWindow = SHOW_WINDOW_FLAGS.Show
                };
                bSuccess = Helpers.SetMultipleTokenPrivileges(hToken, privs);

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to enable the required privileges (Error = 0x{0}).",
                        Marshal.GetLastWin32Error().ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] The required privileges are enabled successfully.");
                }

                ntstatus = NativeMethods.NtDuplicateToken(
                    hToken,
                    ACCESS_MASK.MaximumAllowed,
                    in objectAttributes,
                    BOOLEAN.False,
                    TOKEN_TYPE.Primary,
                    out IntPtr hDupToken);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to duplicate the current process token (Error = 0x{0}).",
                        ntstatus.ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] The current process token is duplicated successfully.");
                }

                Helpers.SetAllTokenPrivileges(hDupToken, true);
                bSuccess = Helpers.SetTokenSessionId(hDupToken, nSessionId);

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Faile to set token session ID to the GUI's one (Error = 0x{0}).",
                        Marshal.GetLastWin32Error().ToString("X8"));
                    NativeMethods.NtClose(hDupToken);
                    break;
                }
                else
                {
                    Console.WriteLine("[+] The token session ID is set to the GUI's one successfully.");
                }

                bSuccess = NativeMethods.CreateProcessAsUser(
                    hDupToken,
                    null,
                    command,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    PROCESS_CREATION_FLAGS.CreateBreakawayFromJob | PROCESS_CREATION_FLAGS.CreateNewConsole,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfo,
                    out PROCESS_INFORMATION processInfo);
                NativeMethods.NtClose(hDupToken);

                if (bSuccess)
                {
                    Console.WriteLine("[+] A desktop process is created successfully (PID: {0}).",
                        processInfo.dwProcessId);
                    NativeMethods.NtClose(processInfo.hThread);
                    NativeMethods.NtClose(processInfo.hProcess);
                }
                else
                {
                    Console.WriteLine("[-] Failed to create a desktop process (Error = 0x{0}).",
                        Marshal.GetLastWin32Error().ToString("X8"));
                }
            } while (false);

            NativeMethods.NtClose(hToken);

            return bSuccess;
        }


        public static bool GetSystemTaskProcess(
            string username,
            string domain,
            string password,
            string taskName,
            string binpath,
            string arguments)
        {
            bool bSuccess;
            bool bImpersonated = false;

            if (!string.IsNullOrEmpty(username))
            {
                Console.WriteLine("[*] Credentials are specified.");
                Console.WriteLine("    [*] Username : {0}", username);
                Console.WriteLine("    [*] Domain   : {0}", domain ?? "(null)");
                Console.WriteLine("    [*] Password : {0}", password ?? "(null)");

                bSuccess = Helpers.GetTokenIntegrityLevel(
                    new IntPtr(-4),
                    out MANDATORY_LABEL_RID baselevel);

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to get current integrity level (Error = 0x{0}).",
                        Marshal.GetLastWin32Error().ToString("X8"));
                    return false;
                }

                Console.WriteLine("[*] Trying to impersonate the specified user.");
                bSuccess = NativeMethods.LogonUserExW(
                    username,
                    domain,
                    password,
                    LOGON_TYPE.Batch,
                    LOGON_PROVIDER.Default,
                    out IntPtr hLogonToken,
                    out IntPtr pSid,
                    out IntPtr _,
                    out int _,
                    out QUOTA_LIMITS _);

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to logon as the specified user (Error = 0x{0})",
                        Marshal.GetLastWin32Error().ToString("X8"));
                    return false;
                }

                bSuccess = Helpers.GetTokenIntegrityLevel(
                    hLogonToken,
                    out MANDATORY_LABEL_RID logonlevel);

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to get integrity level information from the logon token (Error = 0x{0}).",
                        Marshal.GetLastWin32Error().ToString("X8"));
                }
                else
                {
                    if (logonlevel > baselevel)
                        Helpers.AdjustTokenIntegrityLevel(hLogonToken, baselevel);

                    bImpersonated = Helpers.SetCurrentThreadToken(hLogonToken);

                    if (!bImpersonated)
                    {
                        Console.WriteLine("[-] Failed to imperosnate (Error = 0x{0}).",
                            Marshal.GetLastWin32Error().ToString("X8"));
                    }
                }

                NativeMethods.LocalFree(pSid);
                NativeMethods.NtClose(hLogonToken);

                if (!bImpersonated)
                    return false;
                else
                    Console.WriteLine("[+] Impersonation is successful.");
            }

            if (!Helpers.IsLocalAdminEnabledToken(new IntPtr(-6)))
                Console.WriteLine(@"[!] BUILTIN\Administrators group is unavailable. Trial should be failed.");

            Console.WriteLine("[*] Trying to create a scheduled task.");
            Console.WriteLine("    [*] Task Path  : \\{0}", taskName);
            Console.WriteLine("    [*] Executable : {0}", binpath);
            Console.WriteLine("    [*] Arguments  : {0}", arguments);
            bSuccess = Utilities.CreateSystemExecTask(
                taskName,
                binpath,
                arguments,
                out Exception ex);

            if (bImpersonated)
                Helpers.RevertToSelf();

            if (bSuccess)
                Console.WriteLine("[+] A scheduled task process is created successfully.");
            else
                Console.WriteLine("[-] Failed to create a scheduled task process: {0}", ex.Message);

            return bSuccess;
        }
    }
}
