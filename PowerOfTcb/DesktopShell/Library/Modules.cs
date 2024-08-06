using System;
using System.Runtime.InteropServices;
using DesktopShell.Interop;

namespace DesktopShell.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool GetDesktopShell()
        {
            bool bSuccess = false;

            Console.WriteLine("[>] Trying to create desktop shell.");

            if (!Helpers.EnableSeTcbPrivilege())
                Console.WriteLine("[!] SeTcbPrivilege is not available. This trial should be fail.");
            else
                Console.WriteLine("[+] SeTcbPrivilege is enabled successfully.");

            do
            {
                NTSTATUS ntstatus;
                IntPtr pInfoBuffer;
                var objectAttributes = new OBJECT_ATTRIBUTES
                {
                    Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
                };
                var startupInfo = new STARTUPINFO
                {
                    cb = Marshal.SizeOf(typeof(STARTUPINFO)),
                    wShowWindow = SHOW_WINDOW_FLAGS.SW_SHOW,
                    lpDesktop = @"Winsta0\Default"
                };
                int nGuiSessionId = Helpers.GetGuiSessionId();

                if (nGuiSessionId == -1)
                {
                    Console.WriteLine("[-] Failed to get GUI session ID (Error = 0x{0}).", Marshal.GetLastWin32Error().ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] GUI session ID is {0}.", nGuiSessionId);
                }

                ntstatus = NativeMethods.NtOpenProcessToken(
                    new IntPtr(-1),
                    ACCESS_MASK.TOKEN_DUPLICATE,
                    out IntPtr hToken);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to NtOpenProcessToken() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Current token is opened successfully.");
                }

                ntstatus = NativeMethods.NtDuplicateToken(
                    hToken,
                    ACCESS_MASK.MAXIMUM_ALLOWED,
                    in objectAttributes,
                    BOOLEAN.FALSE,
                    TOKEN_TYPE.Primary,
                    out IntPtr hDupToken);
                NativeMethods.NtClose(hToken);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to NtDuplicateToken() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Current token is duplicated successfully (Handle = 0x{0}).", hDupToken.ToString("X"));
                }

                pInfoBuffer = Marshal.AllocHGlobal(4);
                Marshal.WriteInt32(pInfoBuffer, nGuiSessionId);
                ntstatus = NativeMethods.NtSetInformationToken(
                    hDupToken,
                    TOKEN_INFORMATION_CLASS.TokenSessionId,
                    pInfoBuffer,
                    4u);
                Marshal.FreeHGlobal(pInfoBuffer);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to NtSetInformationToken() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                    NativeMethods.NtClose(hDupToken);
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Token Session ID is updated successfully.");
                }

                bSuccess = NativeMethods.CreateProcessAsUser(
                    hDupToken,
                    null,
                    Environment.GetEnvironmentVariable("COMSPEC"),
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    PROCESS_CREATION_FLAGS.CREATE_BREAKAWAY_FROM_JOB | PROCESS_CREATION_FLAGS.CREATE_NEW_CONSOLE,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfo,
                    out PROCESS_INFORMATION processInfo);
                NativeMethods.NtClose(hDupToken);

                if (bSuccess)
                {
                    Console.WriteLine("[+] {0} is executed in desktop session (PID: {1}).",
                        Environment.GetEnvironmentVariable("COMSPEC"),
                        processInfo.dwProcessId);
                    NativeMethods.NtClose(processInfo.hThread);
                    NativeMethods.NtClose(processInfo.hProcess);
                }
                else
                {
                    Console.WriteLine("[-] Failed to CreateProcessAsUser() (Error = 0x{0}).", Marshal.GetLastWin32Error().ToString("X8"));
                }
            } while (false);

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        public static bool GetShell()
        {
            bool bSuccess;
            var startupInfo = new STARTUPINFO
            {
                cb = Marshal.SizeOf(typeof(STARTUPINFO)),
                wShowWindow = SHOW_WINDOW_FLAGS.SW_SHOW,
                lpDesktop = @"Winsta0\Default"
            };

            Console.WriteLine("[>] Simply executing CreateProcess().");
            bSuccess = NativeMethods.CreateProcess(
                null,
                Environment.GetEnvironmentVariable("COMSPEC"),
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                PROCESS_CREATION_FLAGS.CREATE_NEW_CONSOLE,
                IntPtr.Zero,
                Environment.CurrentDirectory,
                in startupInfo,
                out PROCESS_INFORMATION processInfo);

            if (!bSuccess)
            {
                Console.WriteLine("[-] Failed to CreateProcess() (Error = 0x{0}).", Marshal.GetLastWin32Error().ToString("X8"));
            }
            else
            {
                Console.WriteLine("[+] {0} is executed successfully (PID: {1}).",
                    Environment.GetEnvironmentVariable("COMSPEC"),
                    processInfo.dwProcessId);
                NativeMethods.NtClose(processInfo.hThread);
                NativeMethods.NtClose(processInfo.hProcess);
            }

            return bSuccess;
        }
    }
}
