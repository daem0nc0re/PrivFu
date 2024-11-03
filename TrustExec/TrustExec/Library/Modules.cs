using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using TrustExec.Interop;

namespace TrustExec.Library
{
    internal class Modules
    {
        public static bool LookupAccountSid(string accountName, string strSid)
        {
            bool bSuccess = false;
            strSid = strSid.ToUpper();

            if (!string.IsNullOrEmpty(accountName) && !string.IsNullOrEmpty(strSid))
            {
                Console.WriteLine("[-] Account name and SID cannot be specified at a time.");
            }
            else if (string.IsNullOrEmpty(accountName) && string.IsNullOrEmpty(strSid))
            {
                Console.WriteLine("[-] No input.");
            }
            else
            {
                SID_NAME_USE sidType;

                if (!string.IsNullOrEmpty(accountName))
                    bSuccess = Helpers.ConvertAccountNameToSid(ref accountName, out strSid, out sidType);
                else
                    bSuccess = Helpers.ConvertSidToAccountName(ref strSid, out accountName, out sidType);

                if (bSuccess)
                {
                    Console.WriteLine("[*] Account Name : {0}", accountName);
                    Console.WriteLine("[*] Account SID  : {0}", strSid);
                    Console.WriteLine("[*] Account Type : {0}", sidType.ToString());
                }
                else
                {
                    Console.WriteLine("[-] Failed to lookup \"{0}\".", string.IsNullOrEmpty(accountName) ? strSid : accountName);
                }
            }

            return bSuccess;
        }


        public static bool RunTrustedInstallerProcess(string command, bool bNewConsole, in List<string> extraGroupSids)
        {
            int nDosErrorCode;
            bool bReverted = false;
            var requiredPrivs = new List<SE_PRIVILEGE_ID>
            {
                SE_PRIVILEGE_ID.SeDebugPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege
            };
            bool bSuccess = Helpers.EnableTokenPrivileges(
                in requiredPrivs,
                out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs);
            nDosErrorCode = Marshal.GetLastWin32Error();

            foreach (var priv in adjustedPrivs)
            {
                if (priv.Value)
                    Console.WriteLine("[+] {0} is enabled successfully.", priv.Key);
                else
                    Console.WriteLine("[-] Failed to enable {0}.", priv.Key);
            }

            if (!bSuccess)
            {
                Console.WriteLine("[-] Insufficient privileges (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                return false;
            }

            requiredPrivs = new List<SE_PRIVILEGE_ID> {
                SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege,
                SE_PRIVILEGE_ID.SeCreateTokenPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege
            };

            if (bNewConsole)
                requiredPrivs.Add(SE_PRIVILEGE_ID.SeTcbPrivilege);

            bSuccess = Utilities.ImpersonateAsSmss(in requiredPrivs, out adjustedPrivs);

            if (!bSuccess)
            {
                nDosErrorCode = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to impersonate as smss.exe (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
            }
            else
            {
                Console.WriteLine("[+] Impersonation as smss.exe is successful.");
                bSuccess = adjustedPrivs[SE_PRIVILEGE_ID.SeCreateTokenPrivilege];
                bSuccess &= (adjustedPrivs[SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege] ||
                    adjustedPrivs[SE_PRIVILEGE_ID.SeImpersonatePrivilege]);

                if (bNewConsole)
                    bSuccess &= adjustedPrivs[SE_PRIVILEGE_ID.SeTcbPrivilege];

                if (!bSuccess)
                {
                    foreach (var priv in adjustedPrivs)
                    {
                        if (!priv.Value)
                            Console.WriteLine("[-] Failed to enable {0} for current thread.", priv.Key);
                    }

                    Helpers.RevertThreadToken(new IntPtr(-2));
                }
                else
                {
                    foreach (var priv in adjustedPrivs)
                    {
                        if (priv.Value)
                            Console.WriteLine("[+] {0} is enabled successfully for current thread.", priv.Key);
                    }
                }
            }

            if (!bSuccess)
                return false;

            do
            {
                var hToken = Utilities.CreateTrustedInstallerToken(TOKEN_TYPE.Primary, extraGroupSids);

                if (hToken == IntPtr.Zero)
                {
                    nDosErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create a TrustedInstaller token (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                    bSuccess = false;
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a TrustedInstaller token (Handle = 0x{0}).", hToken.ToString("X"));
                    Helpers.EnableAllTokenPrivileges(hToken, out Dictionary<SE_PRIVILEGE_ID, bool> _);

                    if (bNewConsole)
                    {
                        var nSessionId = Helpers.GetGuiSessionId();
                        Helpers.SetTokenSessionId(hToken, nSessionId);
                    }
                }

                bSuccess = Utilities.CreateTokenAssignedSuspendedProcess(
                    hToken,
                    command,
                    ref bNewConsole,
                    out PROCESS_INFORMATION processInfo);
                NativeMethods.NtClose(hToken);

                if (!bSuccess)
                {
                    nDosErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create a token assined process (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                }
                else
                {
                    Console.WriteLine("[+] Got a token assigned process (PID: {0}).", processInfo.dwProcessId);
                    bReverted = Helpers.RevertThreadToken(new IntPtr(-2));
                    NativeMethods.NtResumeThread(processInfo.hThread, out uint _);

                    if (!bNewConsole)
                        NativeMethods.NtWaitForSingleObject(processInfo.hProcess, false, IntPtr.Zero);

                    NativeMethods.NtClose(processInfo.hThread);
                    NativeMethods.NtClose(processInfo.hProcess);
                }
            } while (false);

            if (!bReverted)
                Helpers.RevertThreadToken(new IntPtr(-2));

            return bSuccess;
        }


        public static bool RunTrustedInstallerProcessWithS4ULogon(string command, bool bNewConsole, in List<string> extraGroupSids)
        {
            int nDosErrorCode;
            bool bReverted = false;
            var requiredPrivs = new List<SE_PRIVILEGE_ID>
            {
                SE_PRIVILEGE_ID.SeDebugPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege
            };
            bool bSuccess = Helpers.EnableTokenPrivileges(
                in requiredPrivs,
                out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs);
            nDosErrorCode = Marshal.GetLastWin32Error();

            foreach (var priv in adjustedPrivs)
            {
                if (priv.Value)
                    Console.WriteLine("[+] {0} is enabled successfully.", priv.Key);
                else
                    Console.WriteLine("[-] Failed to enable {0}.", priv.Key);
            }

            if (!bSuccess)
            {
                Console.WriteLine("[-] Insufficient privileges (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                return false;
            }

            bSuccess = Utilities.GetS4uLogonAccount(
                    out string upn,
                    out string domain,
                    out LSA_STRING pkgName,
                    out TOKEN_SOURCE tokenSource);

            if (!bSuccess)
            {
                nDosErrorCode = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get S4U logon information (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
            }
            else
            {
                string accountName;
                string tokenSourceName = Encoding.ASCII.GetString(tokenSource.SourceName);

                if (string.Compare(tokenSourceName, "User32", true) < 0)
                    accountName = string.Format("{0}@{1}", upn, domain);
                else
                    accountName = string.Format(@"{0}\{1}", domain, upn);

                Console.WriteLine("[*] S4U logon account is \"{0}\" (Package: {1}).", accountName, pkgName.ToString());
            }

            requiredPrivs = new List<SE_PRIVILEGE_ID> {
                SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege,
                SE_PRIVILEGE_ID.SeTcbPrivilege
            };
            bSuccess = Utilities.ImpersonateAsSmss(in requiredPrivs, out adjustedPrivs);

            if (!bSuccess)
            {
                nDosErrorCode = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to impersonate as smss.exe (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
            }
            else
            {
                Console.WriteLine("[+] Impersonation as smss.exe is successful.");
                bSuccess = adjustedPrivs[SE_PRIVILEGE_ID.SeTcbPrivilege];
                bSuccess &= (adjustedPrivs[SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege] ||
                    adjustedPrivs[SE_PRIVILEGE_ID.SeImpersonatePrivilege]);

                if (!bSuccess)
                {
                    foreach (var priv in adjustedPrivs)
                    {
                        if (!priv.Value)
                            Console.WriteLine("[-] Failed to enable {0} for current thread.", priv.Key);
                    }

                    Helpers.RevertThreadToken(new IntPtr(-2));
                }
                else
                {
                    foreach (var priv in adjustedPrivs)
                    {
                        if (priv.Value)
                            Console.WriteLine("[+] {0} is enabled successfully for current thread.", priv.Key);
                    }
                }
            }

            if (!bSuccess)
                return false;

            do
            {
                IntPtr hToken = Utilities.GetTrustedInstallerTokenWithS4uLogon(upn, domain, in pkgName, in tokenSource, in extraGroupSids);

                if (hToken == IntPtr.Zero)
                {
                    nDosErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create a S4U logon token (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                    bSuccess = false;
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a S4U logon token (Handle = 0x{0}).", hToken.ToString("X"));
                    Helpers.EnableAllTokenPrivileges(hToken, out Dictionary<SE_PRIVILEGE_ID, bool> _);

                    if (bNewConsole)
                    {
                        var nSessionId = Helpers.GetGuiSessionId();
                        Helpers.SetTokenSessionId(hToken, nSessionId);
                    }
                }

                bSuccess = Utilities.CreateTokenAssignedSuspendedProcess(
                    hToken,
                    command,
                    ref bNewConsole,
                    out PROCESS_INFORMATION processInfo);
                NativeMethods.NtClose(hToken);

                if (!bSuccess)
                {
                    nDosErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create a token assined process (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                }
                else
                {
                    Console.WriteLine("[+] Got a token assigned process (PID: {0}).", processInfo.dwProcessId);
                    bReverted = Helpers.RevertThreadToken(new IntPtr(-2));
                    NativeMethods.NtResumeThread(processInfo.hThread, out uint _);

                    if (!bNewConsole)
                        NativeMethods.NtWaitForSingleObject(processInfo.hProcess, false, IntPtr.Zero);

                    NativeMethods.NtClose(processInfo.hThread);
                    NativeMethods.NtClose(processInfo.hProcess);
                }
            } while (false);

            if (!bReverted)
                Helpers.RevertThreadToken(new IntPtr(-2));

            return bSuccess;
        }


        public static bool RunTrustedInstallerProcessWithService(string command, bool bNewConsole)
        {
            int nDosErrorCode;
            bool bReverted = false;
            var requiredPrivs = new List<SE_PRIVILEGE_ID>
            {
                SE_PRIVILEGE_ID.SeDebugPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege
            };
            bool bSuccess = Helpers.EnableTokenPrivileges(
                in requiredPrivs,
                out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs);
            nDosErrorCode = Marshal.GetLastWin32Error();

            foreach (var priv in adjustedPrivs)
            {
                if (priv.Value)
                    Console.WriteLine("[+] {0} is enabled successfully.", priv.Key);
                else
                    Console.WriteLine("[-] Failed to enable {0}.", priv.Key);
            }

            if (!bSuccess)
            {
                Console.WriteLine("[-] Insufficient privileges (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                return false;
            }

            requiredPrivs = new List<SE_PRIVILEGE_ID> {
                SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege,
                SE_PRIVILEGE_ID.SeDebugPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege,
                SE_PRIVILEGE_ID.SeTcbPrivilege
            };
            bSuccess = Utilities.ImpersonateAsSmss(in requiredPrivs, out adjustedPrivs);

            if (!bSuccess)
            {
                nDosErrorCode = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to impersonate as smss.exe (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
            }
            else
            {
                Console.WriteLine("[+] Impersonation as smss.exe is successful.");
                bSuccess = adjustedPrivs[SE_PRIVILEGE_ID.SeTcbPrivilege];
                bSuccess &= (adjustedPrivs[SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege] ||
                    adjustedPrivs[SE_PRIVILEGE_ID.SeImpersonatePrivilege]);

                if (!bSuccess)
                {
                    foreach (var priv in adjustedPrivs)
                    {
                        if (!priv.Value)
                            Console.WriteLine("[-] Failed to enable {0} for current thread.", priv.Key);
                    }

                    Helpers.RevertThreadToken(new IntPtr(-2));
                }
                else
                {
                    foreach (var priv in adjustedPrivs)
                    {
                        if (priv.Value)
                            Console.WriteLine("[+] {0} is enabled successfully for current thread.", priv.Key);
                    }
                }
            }

            if (!bSuccess)
                return false;

            do
            {
                var hToken = IntPtr.Zero;

                try
                {
                    using(var query = new ServiceQuery())
                    {
                        int pid;
                        var nPidOffset = Marshal.OffsetOf(typeof(SERVICE_STATUS_PROCESS), "dwProcessId").ToInt32();
                        var serviceName = "TrustedInstaller";
                        IntPtr pInfoBuffer = query.GetServiceStatus(serviceName);

                        if (pInfoBuffer == IntPtr.Zero)
                        {
                            nDosErrorCode = Marshal.GetLastWin32Error();
                            Console.WriteLine("[-] Failed to get status of {0} service (Error = 0x{1}).",
                                serviceName,
                                nDosErrorCode.ToString("X8"));
                            break;
                        }
                        else
                        {
                            pid = Marshal.ReadInt32(pInfoBuffer, nPidOffset);
                            Marshal.FreeHGlobal(pInfoBuffer);
                        }

                        if (pid <= 0)
                        {
                            nDosErrorCode = Marshal.GetLastWin32Error();
                            Console.WriteLine("[>] {0} service is not running. Trying to start {0} service.", serviceName);
                            bSuccess = query.StartService(serviceName);

                            if (!bSuccess)
                            {
                                nDosErrorCode = Marshal.GetLastWin32Error();
                                Console.WriteLine("[-] Failed to start {0} servce (Error = 0x{1}).",
                                    serviceName,
                                    nDosErrorCode.ToString("X8"));
                                break;
                            }
                            else
                            {
                                pInfoBuffer = query.GetServiceStatus(serviceName);

                                if (pInfoBuffer == IntPtr.Zero)
                                {
                                    Console.WriteLine("[-] Failed to get status of {0} service (Error = 0x{1}).",
                                        serviceName,
                                        nDosErrorCode.ToString("X8"));
                                    break;
                                }
                                else
                                {
                                    pid = Marshal.ReadInt32(pInfoBuffer, nPidOffset);
                                    Marshal.FreeHGlobal(pInfoBuffer);
                                }

                                if (pid <= 0)
                                {
                                    Console.WriteLine("[-] Failed to get PID of {0} service process.", serviceName);
                                    break;
                                }
                                else
                                {
                                    Console.WriteLine("[+] {0} service is started successfully (PID: {1}).", serviceName, pid);
                                }

                                hToken = Helpers.GetProcessToken(pid, TOKEN_TYPE.Primary);
                                bSuccess = query.StopService(serviceName);
                                nDosErrorCode = Marshal.GetLastWin32Error();

                                if (!bSuccess)
                                {
                                    Console.WriteLine("[-] Failed to stop {0} service (Error = 0x{1}).",
                                        serviceName,
                                        nDosErrorCode.ToString("X8"));
                                }
                                else
                                {
                                    Console.WriteLine("[+] {0} service is stopped successfully.", serviceName);
                                }
                            }
                        }
                    }
                }
                catch
                {
                    Console.WriteLine("[-] Failed to query service manager.");
                    break;
                }

                if (hToken == IntPtr.Zero)
                {
                    nDosErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to duplicate a service token (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                    bSuccess = false;
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a service token (Handle = 0x{0}).", hToken.ToString("X"));
                    Helpers.EnableAllTokenPrivileges(hToken, out Dictionary<SE_PRIVILEGE_ID, bool> _);

                    if (bNewConsole)
                    {
                        var nSessionId = Helpers.GetGuiSessionId();
                        Helpers.SetTokenSessionId(hToken, nSessionId);
                    }
                }

                bSuccess = Utilities.CreateTokenAssignedSuspendedProcess(
                    hToken,
                    command,
                    ref bNewConsole,
                    out PROCESS_INFORMATION processInfo);
                NativeMethods.NtClose(hToken);

                if (!bSuccess)
                {
                    nDosErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create a token assined process (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                }
                else
                {
                    Console.WriteLine("[+] Got a token assigned process (PID: {0}).", processInfo.dwProcessId);
                    bReverted = Helpers.RevertThreadToken(new IntPtr(-2));
                    NativeMethods.NtResumeThread(processInfo.hThread, out uint _);

                    if (!bNewConsole)
                        NativeMethods.NtWaitForSingleObject(processInfo.hProcess, false, IntPtr.Zero);

                    NativeMethods.NtClose(processInfo.hThread);
                    NativeMethods.NtClose(processInfo.hProcess);
                }
            } while (false);

            if (!bReverted)
                Helpers.RevertThreadToken(new IntPtr(-2));

            return bSuccess;
        }


        public static bool RunTrustedInstallerProcessWithServiceLogon(string command, bool bNewConsole, in List<string> extraGroupSids)
        {
            int nDosErrorCode;
            bool bReverted = false;
            var requiredPrivs = new List<SE_PRIVILEGE_ID>
            {
                SE_PRIVILEGE_ID.SeDebugPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege
            };
            bool bSuccess = Helpers.EnableTokenPrivileges(
                in requiredPrivs,
                out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs);
            nDosErrorCode = Marshal.GetLastWin32Error();

            foreach (var priv in adjustedPrivs)
            {
                if (priv.Value)
                    Console.WriteLine("[+] {0} is enabled successfully.", priv.Key);
                else
                    Console.WriteLine("[-] Failed to enable {0}.", priv.Key);
            }

            if (!bSuccess)
            {
                Console.WriteLine("[-] Insufficient privileges (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                return false;
            }

            requiredPrivs = new List<SE_PRIVILEGE_ID> {
                SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege,
                SE_PRIVILEGE_ID.SeTcbPrivilege
            };
            bSuccess = Utilities.ImpersonateAsSmss(in requiredPrivs, out adjustedPrivs);

            if (!bSuccess)
            {
                nDosErrorCode = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to impersonate as smss.exe (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
            }
            else
            {
                Console.WriteLine("[+] Impersonation as smss.exe is successful.");
                bSuccess = adjustedPrivs[SE_PRIVILEGE_ID.SeTcbPrivilege];
                bSuccess &= (adjustedPrivs[SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege] ||
                    adjustedPrivs[SE_PRIVILEGE_ID.SeImpersonatePrivilege]);

                if (!bSuccess)
                {
                    foreach (var priv in adjustedPrivs)
                    {
                        if (!priv.Value)
                            Console.WriteLine("[-] Failed to enable {0} for current thread.", priv.Key);
                    }

                    Helpers.RevertThreadToken(new IntPtr(-2));
                }
                else
                {
                    foreach (var priv in adjustedPrivs)
                    {
                        if (priv.Value)
                            Console.WriteLine("[+] {0} is enabled successfully for current thread.", priv.Key);
                    }
                }
            }

            if (!bSuccess)
                return false;

            do
            {
                IntPtr hToken = Utilities.GetTrustedInstallerTokenWithServiceLogon("LOCAL SERVICE", "NT AUTHORITY", in extraGroupSids);

                if (hToken == IntPtr.Zero)
                {
                    nDosErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create a service logon token (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                    bSuccess = false;
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a service logon token (Handle = 0x{0}).", hToken.ToString("X"));
                    Helpers.EnableAllTokenPrivileges(hToken, out Dictionary<SE_PRIVILEGE_ID, bool> _);

                    if (bNewConsole)
                    {
                        var nSessionId = Helpers.GetGuiSessionId();
                        Helpers.SetTokenSessionId(hToken, nSessionId);
                    }
                }

                bSuccess = Utilities.CreateTokenAssignedSuspendedProcess(
                    hToken,
                    command,
                    ref bNewConsole,
                    out PROCESS_INFORMATION processInfo);
                NativeMethods.NtClose(hToken);

                if (!bSuccess)
                {
                    nDosErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create a token assined process (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                }
                else
                {
                    Console.WriteLine("[+] Got a token assigned process (PID: {0}).", processInfo.dwProcessId);
                    bReverted = Helpers.RevertThreadToken(new IntPtr(-2));
                    NativeMethods.NtResumeThread(processInfo.hThread, out uint _);

                    if (!bNewConsole)
                        NativeMethods.NtWaitForSingleObject(processInfo.hProcess, false, IntPtr.Zero);

                    NativeMethods.NtClose(processInfo.hThread);
                    NativeMethods.NtClose(processInfo.hProcess);
                }
            } while (false);

            if (!bReverted)
                Helpers.RevertThreadToken(new IntPtr(-2));

            return bSuccess;
        }


        public static bool RunTrustedInstallerProcessWithVirtualLogon(string command, bool bNewConsole, in List<string> extraGroupSids)
        {
            int nDosErrorCode;
            bool bReverted = false;
            bool bDomainExists = false;
            var virtualDomainName = "VirtualDomain";
            var requiredPrivs = new List<SE_PRIVILEGE_ID>
            {
                SE_PRIVILEGE_ID.SeDebugPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege
            };
            bool bSuccess = Helpers.EnableTokenPrivileges(
                in requiredPrivs,
                out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs);
            nDosErrorCode = Marshal.GetLastWin32Error();

            foreach (var priv in adjustedPrivs)
            {
                if (priv.Value)
                    Console.WriteLine("[+] {0} is enabled successfully.", priv.Key);
                else
                    Console.WriteLine("[-] Failed to enable {0}.", priv.Key);
            }

            if (!bSuccess)
            {
                Console.WriteLine("[-] Insufficient privileges (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                return false;
            }

            requiredPrivs = new List<SE_PRIVILEGE_ID> {
                SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege,
                SE_PRIVILEGE_ID.SeImpersonatePrivilege,
                SE_PRIVILEGE_ID.SeTcbPrivilege
            };
            bSuccess = Utilities.ImpersonateAsSmss(in requiredPrivs, out adjustedPrivs);

            if (!bSuccess)
            {
                nDosErrorCode = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to impersonate as smss.exe (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
            }
            else
            {
                Console.WriteLine("[+] Impersonation as smss.exe is successful.");
                bSuccess = adjustedPrivs[SE_PRIVILEGE_ID.SeTcbPrivilege];
                bSuccess &= (adjustedPrivs[SE_PRIVILEGE_ID.SeAssignPrimaryTokenPrivilege] ||
                    adjustedPrivs[SE_PRIVILEGE_ID.SeImpersonatePrivilege]);

                if (!bSuccess)
                {
                    foreach (var priv in adjustedPrivs)
                    {
                        if (!priv.Value)
                            Console.WriteLine("[-] Failed to enable {0} for current thread.", priv.Key);
                    }

                    Helpers.RevertThreadToken(new IntPtr(-2));
                }
                else
                {
                    foreach (var priv in adjustedPrivs)
                    {
                        if (priv.Value)
                            Console.WriteLine("[+] {0} is enabled successfully for current thread.", priv.Key);
                    }
                }
            }

            if (!bSuccess)
                return false;

            do
            {
                IntPtr hToken;
                var virtualAccountName = "VirtualAdmin";
                var domainSid = "S-1-5-110";
                var accountSid = string.Format("{0}-500", domainSid);
                bSuccess = Helpers.AddSidMapping(virtualDomainName, null, domainSid);

                if (!bSuccess)
                {
                    nDosErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create a LocalService token (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                }
                else
                {
                    Console.WriteLine(@"[+] A virtual domain {0} is created successfully (SID: {1}).", virtualDomainName, domainSid);
                    bDomainExists = true;
                    bSuccess = Helpers.AddSidMapping(virtualDomainName, virtualAccountName, accountSid);

                    if (!bSuccess)
                    {
                        nDosErrorCode = Marshal.GetLastWin32Error();
                        Console.WriteLine("[-] Failed to create a LocalService token (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                    }
                    else
                    {
                        Console.WriteLine(@"[+] A virtual account {0}\{1} is created successfully (SID: {2}).",
                            virtualDomainName,
                            virtualAccountName,
                            accountSid);
                    }
                }

                if (!bSuccess)
                    break;

                hToken = Utilities.GetTrustedInstallerTokenWithVirtualLogon(virtualAccountName, virtualDomainName, in extraGroupSids);

                if (hToken == IntPtr.Zero)
                {
                    nDosErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create a virtual logon token (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                    bSuccess = false;
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a virtual logon token (Handle = 0x{0}).", hToken.ToString("X"));
                    Helpers.EnableAllTokenPrivileges(hToken, out Dictionary<SE_PRIVILEGE_ID, bool> _);

                    if (bNewConsole)
                    {
                        var nSessionId = Helpers.GetGuiSessionId();
                        Helpers.SetTokenSessionId(hToken, nSessionId);
                    }
                }

                bSuccess = Utilities.CreateTokenAssignedSuspendedProcess(
                    hToken,
                    command,
                    ref bNewConsole,
                    out PROCESS_INFORMATION processInfo);
                NativeMethods.NtClose(hToken);

                if (!bSuccess)
                {
                    nDosErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create a token assined process (Error = 0x{0}).", nDosErrorCode.ToString("X8"));
                }
                else
                {
                    Console.WriteLine("[+] Got a token assigned process (PID: {0}).", processInfo.dwProcessId);

                    if (Helpers.RemoveSidMapping(virtualDomainName, null))
                    {
                        bDomainExists = false;
                        Console.WriteLine("[+] {0} domain is removed successfully.", virtualDomainName);
                    }
                    else
                    {
                        nDosErrorCode = Marshal.GetLastWin32Error();
                        Console.WriteLine("[-] Failed to remove {0} domain (Error = 0x{0}).", virtualDomainName, nDosErrorCode.ToString("X8"));
                    }

                    bReverted = Helpers.RevertThreadToken(new IntPtr(-2));
                    NativeMethods.NtResumeThread(processInfo.hThread, out uint _);

                    if (!bNewConsole)
                        NativeMethods.NtWaitForSingleObject(processInfo.hProcess, false, IntPtr.Zero);

                    NativeMethods.NtClose(processInfo.hThread);
                    NativeMethods.NtClose(processInfo.hProcess);
                }
            } while (false);

            if (!bSuccess && bDomainExists)
            {
                if (Helpers.RemoveSidMapping(virtualDomainName, null))
                {
                    Console.WriteLine("[+] {0} domain is removed successfully.", virtualDomainName);
                }
                else
                {
                    nDosErrorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to remove {0} domain (Error = 0x{0}).", virtualDomainName, nDosErrorCode.ToString("X8"));
                }
            }

            if (!bReverted)
                Helpers.RevertThreadToken(new IntPtr(-2));

            return bSuccess;
        }
    }
}
