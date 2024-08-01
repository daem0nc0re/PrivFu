using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using TokenDump.Interop;

namespace TokenDump.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool GetProcessTokenInformation(string accountFilter, bool debug)
        {
            var uniqueUsers = new List<string>();
            var info = new List<BriefTokenInformation>();

            if (debug)
            {
                Console.WriteLine("[>] Trying to enable SeDebugPrivilege.");

                if (Helpers.EnableTokenPrivileges(
                    new List<SE_PRIVILEGE_ID> { SE_PRIVILEGE_ID.SeDebugPrivilege },
                    out Dictionary<SE_PRIVILEGE_ID, bool> _))
                {
                    Console.WriteLine("[+] SeDebugPrivilege is enabled successfully.");
                }
                else
                {
                    Console.WriteLine("[-] SeDebugPrivilege is not available.");
                    return false;
                }
            }

            Console.WriteLine("[>] Trying to enumerate process token.");

            foreach (var proc in Process.GetProcesses())
            {
                if (Utilities.GetBriefTokenInformationFromProcess(
                    proc.Id,
                    out BriefTokenInformation entry))
                {
                    if (!uniqueUsers.Contains(entry.TokenUserName))
                        uniqueUsers.Add(entry.TokenUserName);

                    info.Add(entry);
                }
            }

            Utilities.DumpBriefProcessInformation(info, accountFilter, out int nEntryCount);
            info.Clear();

            if (nEntryCount == 0)
                Console.WriteLine("[-] Failed to enumerate process token.");
            else
                Console.WriteLine("[+] Got {0} token information.", nEntryCount);

            if (uniqueUsers.Count > 0)
            {
                Console.WriteLine("[*] Found {0} account(s).", uniqueUsers.Count);

                foreach (var user in uniqueUsers)
                    Console.WriteLine("    [*] {0}", user);
            }

            Console.WriteLine("[*] Done.");

            return (nEntryCount > 0);
        }


        public static bool GetThreadTokenInformation(string accountFilter, bool debug)
        {
            int nEntryCount = 0;
            var uniqueUsers = new List<string>();
            var dumpedInfo = new List<BriefTokenInformation>();

            if (debug)
            {
                Console.WriteLine("[>] Trying to enable SeDebugPrivilege.");

                if (Helpers.EnableTokenPrivileges(
                    new List<SE_PRIVILEGE_ID> { SE_PRIVILEGE_ID.SeDebugPrivilege },
                    out Dictionary<SE_PRIVILEGE_ID, bool> _))
                {
                    Console.WriteLine("[+] SeDebugPrivilege is enabled successfully.");
                }
                else
                {
                    Console.WriteLine("[-] SeDebugPrivilege is not available.");
                    return false;
                }
            }

            Console.WriteLine("[>] Trying to enumerate impersonated threads.");

            if (Helpers.GetSystemHandles(
                "Thread",
                out Dictionary<int, List<SYSTEM_HANDLE_TABLE_ENTRY_INFO>> handles))
            {
                foreach (var handleInfo in handles)
                {
                    var status = Utilities.GetBriefThreadTokenInformation(
                        handleInfo.Key,
                        handleInfo.Value,
                        out List<BriefTokenInformation> info);

                    if (status)
                        dumpedInfo.AddRange(info);

                    info.Clear();
                }

                foreach (var threadInfo in dumpedInfo)
                {
                    if (!uniqueUsers.Contains(threadInfo.TokenUserName))
                        uniqueUsers.Add(threadInfo.TokenUserName);
                }

                Utilities.DumpBriefThreadInformation(dumpedInfo, accountFilter, out nEntryCount);
            }

            if (nEntryCount == 0)
            {
                Console.WriteLine("[-] No threads.");
            }
            else
            {
                Console.WriteLine("[+] Got {0} thread(s).", nEntryCount);

                if (uniqueUsers.Count > 0)
                {
                    Console.WriteLine("[*] Found {0} account(s).", uniqueUsers.Count);

                    foreach (var user in uniqueUsers)
                        Console.WriteLine("    [*] {0}", user);
                }
            }

            Console.WriteLine("[*] Done.");

            return (nEntryCount > 0);
        }


        public static bool GetTokenHandleInformation(string accountFilter, int pid, bool debug)
        {
            int nEntryCount = 0;
            var uniqueUsers = new List<string>();

            if (debug)
            {
                Console.WriteLine("[>] Trying to enable SeDebugPrivilege.");

                if (Helpers.EnableTokenPrivileges(
                    new List<SE_PRIVILEGE_ID> { SE_PRIVILEGE_ID.SeDebugPrivilege },
                    out Dictionary<SE_PRIVILEGE_ID, bool> _))
                {
                    Console.WriteLine("[+] SeDebugPrivilege is enabled successfully.");
                }
                else
                {
                    Console.WriteLine("[-] SeDebugPrivilege is not available.");
                    return false;
                }
            }

            Console.WriteLine("[>] Trying to enumerate token handles.");

            if (Helpers.GetSystemHandles(
                "Token",
                out Dictionary<int, List<SYSTEM_HANDLE_TABLE_ENTRY_INFO>> handles))
            {
                if ((pid != 0) && !handles.ContainsKey(pid))
                {
                    Console.WriteLine("[-] Specified PID is not found.");
                }
                else
                {
                    foreach (var handleInfo in handles)
                    {
                        if ((pid != 0) && (handleInfo.Key != pid))
                            continue;

                        var status = Utilities.GetBriefTokenInformationFromHandle(
                            handleInfo.Key,
                            handleInfo.Value,
                            out List<BriefTokenInformation> info);

                        if (status)
                        {
                            Utilities.DumpBriefHandleInformation(
                                info,
                                accountFilter,
                                out int nResultsCount);
                            nEntryCount += nResultsCount;

                            foreach (var entry in info)
                            {
                                if (!uniqueUsers.Contains(entry.TokenUserName))
                                    uniqueUsers.Add(entry.TokenUserName);
                            }
                        }

                        info.Clear();
                    }
                }
            }

            if (nEntryCount == 0)
            {
                Console.WriteLine("[-] No handles.");
            }
            else
            {
                Console.WriteLine("[+] Got {0} handle(s).", nEntryCount);

                if (uniqueUsers.Count > 0)
                {
                    Console.WriteLine("[*] Found {0} account(s).", uniqueUsers.Count);

                    foreach (var user in uniqueUsers)
                        Console.WriteLine("    [*] {0}", user);
                }
            }

            Console.WriteLine("[*] Done.");

            return (nEntryCount > 0);
        }


        public static bool GetVerboseTokenInformation(int pid, int tid, IntPtr hObject, bool debug)
        {
            IntPtr hProcess;
            var hThread = IntPtr.Zero;
            var info = new VerboseTokenInformation { ProcessId = pid, ThreadId = tid, Handle = hObject };
            var status = false;
            var accessMask = ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION;

            if (hObject != IntPtr.Zero)
                accessMask |= ACCESS_MASK.PROCESS_DUP_HANDLE;

            if (debug)
            {
                Console.WriteLine("[>] Trying to enable SeDebugPrivilege.");

                if (Helpers.EnableTokenPrivileges(
                    new List<SE_PRIVILEGE_ID> { SE_PRIVILEGE_ID.SeDebugPrivilege },
                    out Dictionary<SE_PRIVILEGE_ID, bool> _))
                {
                    Console.WriteLine("[+] SeDebugPrivilege is enabled successfully.");
                }
                else
                {
                    Console.WriteLine("[-] SeDebugPrivilege is not available.");
                    return false;
                }
            }

            if (info.ThreadId != 0)
                Console.WriteLine("[>] Trying to dump thread token information.");
            else if (info.Handle == IntPtr.Zero)
                Console.WriteLine("[>] Trying to dump process token information.");
            else
                Console.WriteLine("[>] Trying to dump token handle information.");

            do
            {
                IntPtr hToken;

                if (info.ThreadId == 0)
                {
                    hProcess = NativeMethods.OpenProcess(accessMask, false, info.ProcessId);
                }
                else
                {
                    status = Helpers.OpenRemoteThread(
                        info.ProcessId,
                        info.ThreadId,
                        ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                        ACCESS_MASK.THREAD_QUERY_LIMITED_INFORMATION,
                        out hProcess,
                        out hThread);

                    if (!status)
                        break;
                }

                if (hProcess == IntPtr.Zero)
                {
                    if (Marshal.GetLastWin32Error() == Win32Consts.ERROR_INVALID_PARAMETER)
                        Console.WriteLine("[-] Specified PID is not found.");
                    else if (Marshal.GetLastWin32Error() == Win32Consts.ERROR_ACCESS_DENIED)
                        Console.WriteLine("[-] Access is denied.");
                    else if (info.ThreadId == 0)
                        Console.WriteLine("[-] Failed to open the target process.");
                    else
                        Console.WriteLine("[-] Failed to open the target thread.");

                    break;
                }
                else
                {
                    info.ImageFilePath = Helpers.GetProcessImageFilePath(hProcess);
                    info.CommandLine = Helpers.GetProcessCommandLine(hProcess);

                    if (string.IsNullOrEmpty(info.ImageFilePath))
                        break;
                    else
                        info.ProcessName = Path.GetFileName(info.ImageFilePath);

                    if (string.IsNullOrEmpty(info.CommandLine))
                        info.CommandLine = "N/A";
                }

                if (info.ThreadId != 0)
                {
                    status = NativeMethods.OpenThreadToken(
                        hThread,
                        ACCESS_MASK.TOKEN_QUERY | ACCESS_MASK.TOKEN_QUERY_SOURCE,
                        false,
                        out hToken);

                    if (!status)
                    {
                        status = NativeMethods.OpenThreadToken(
                            hThread,
                            ACCESS_MASK.TOKEN_QUERY,
                            false,
                            out hToken);

                        if (!status)
                            hToken = IntPtr.Zero;
                    }
                }
                else if (info.Handle == IntPtr.Zero)
                {
                    status = NativeMethods.OpenProcessToken(
                        hProcess,
                        ACCESS_MASK.TOKEN_QUERY | ACCESS_MASK.TOKEN_QUERY_SOURCE,
                        out hToken);

                    if (!status)
                    {
                        status = NativeMethods.OpenProcessToken(
                            hProcess,
                            ACCESS_MASK.TOKEN_QUERY,
                            out hToken);

                        if (!status)
                            hToken = IntPtr.Zero;
                    }
                }
                else
                {
                    NTSTATUS ntstatus = NativeMethods.NtDuplicateObject(
                        hProcess,
                        info.Handle,
                        new IntPtr(-1),
                        out hToken,
                        ACCESS_MASK.TOKEN_QUERY | ACCESS_MASK.TOKEN_QUERY_SOURCE,
                        0u,
                        0);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    {
                        ntstatus = NativeMethods.NtDuplicateObject(
                            hProcess,
                            info.Handle,
                            new IntPtr(-1),
                            out hToken,
                            ACCESS_MASK.TOKEN_QUERY,
                            0u,
                            0);
                        status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                        if (!status)
                            hToken = IntPtr.Zero;
                    }
                }

                if (hToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get the specifiled token handle.");
                    break;
                }

                status = Utilities.GetVerboseTokenInformation(
                    hToken,
                    false,
                    out IntPtr hLinkedToken,
                    ref info,
                    out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> privs,
                    out Dictionary<string, SE_GROUP_ATTRIBUTES> groups,
                    out Dictionary<string, SE_GROUP_ATTRIBUTES> restrictedGroups,
                    out Dictionary<string, SE_GROUP_ATTRIBUTES> capabilities,
                    out List<AceInformation> acl);
                info.SecurityAttributesBuffer = Helpers.GetTokenSecurityAttributes(hToken);
                NativeMethods.NtClose(hToken);

                if (status)
                {
                    Utilities.DumpVerboseTokenInformation(info, privs, groups, restrictedGroups, capabilities, acl);

                    if (hLinkedToken != IntPtr.Zero)
                    {
                        info.IsLinkedToken = true;
                        status = Utilities.GetVerboseTokenInformation(
                            hLinkedToken,
                            false,
                            out IntPtr _,
                            ref info,
                            out privs,
                            out groups,
                            out restrictedGroups,
                            out capabilities,
                            out acl);

                        if (status)
                            Utilities.DumpVerboseTokenInformation(info, privs, groups, restrictedGroups, capabilities, acl);

                        NativeMethods.NtClose(hLinkedToken);
                    }
                }
                else
                {
                    Console.WriteLine("[-] Failed to get access.");
                }

                if (info.SecurityAttributesBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(info.SecurityAttributesBuffer);
            } while (false);

            if (hProcess != IntPtr.Zero)
                NativeMethods.NtClose(hProcess);

            if (!status)
                Console.WriteLine("[-] Failed to dump token information.");

            Console.WriteLine("[*] Done.");

            return status;
        }
    }
}
