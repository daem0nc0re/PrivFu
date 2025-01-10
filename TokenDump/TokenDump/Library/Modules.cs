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


        public static bool GetVerboseTokenInformation(int pid, int tid, IntPtr hObject, bool bDebug)
        {
            var hThread = IntPtr.Zero;
            var info = new VerboseTokenInformation { ProcessId = pid, ThreadId = tid, Handle = hObject };
            var bSuccess = false;

            if ((pid != 0) && (tid != 0))
            {
                Console.WriteLine("[-] PID and TID must not be specified at once.");
                return false;
            }
            else if ((info.ProcessId == 0) && (info.ThreadId == 0))
            {
                Console.WriteLine("[-] Missing PID or TID.");
                return false;
            }
            else if ((info.Handle != IntPtr.Zero) && (info.ProcessId == 0))
            {
                Console.WriteLine("[-] Missing handle source PID.");
                return false;
            }

            if (info.Handle != IntPtr.Zero)
            {
                bSuccess = Helpers.GetSystemHandles(
                    "Token",
                    out Dictionary<int, List<SYSTEM_HANDLE_TABLE_ENTRY_INFO>> handles);

                if (bSuccess && handles.ContainsKey(pid))
                {
                    bSuccess = false;

                    foreach (var handle in handles[pid])
                    {
                        if (new IntPtr(handle.HandleValue) == info.Handle)
                        {
                            bSuccess = true;
                            break;
                        }
                    }
                }

                if (!bSuccess)
                {
                    Console.WriteLine("[-] No specified token handle belong to the specifed process.");
                    return false;
                }
            }

            if (bDebug)
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

                if (info.Handle != IntPtr.Zero)
                {
                    hToken = Helpers.DuplicateHandleFromProcess(
                        info.ProcessId,
                        info.Handle,
                        ACCESS_MASK.TOKEN_QUERY | ACCESS_MASK.TOKEN_QUERY_SOURCE);

                    if (hToken == IntPtr.Zero)
                        hToken = Helpers.DuplicateHandleFromProcess(info.ProcessId, info.Handle, ACCESS_MASK.TOKEN_QUERY);
                }
                else if (info.ThreadId != 0)
                {
                    hToken = Helpers.GetThreadToken(
                        info.ThreadId,
                        ACCESS_MASK.TOKEN_QUERY | ACCESS_MASK.TOKEN_QUERY_SOURCE,
                        out info.ProcessId);

                    if (hToken == IntPtr.Zero)
                        hToken = Helpers.GetThreadToken(info.ThreadId, ACCESS_MASK.TOKEN_QUERY, out info.ProcessId);
                }
                else
                {
                    hToken = Helpers.GetProcessToken(
                        info.ProcessId,
                        ACCESS_MASK.TOKEN_QUERY | ACCESS_MASK.TOKEN_QUERY_SOURCE);

                    if (hToken == IntPtr.Zero)
                        hToken = Helpers.GetProcessToken(info.ProcessId, ACCESS_MASK.TOKEN_QUERY);
                }

                if (hToken == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get the specifiled token handle.");
                    break;
                }
                else
                {
                    var objectAttributes = new OBJECT_ATTRIBUTES()
                    {
                        Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
                    };
                    var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(info.ProcessId) };
                    NTSTATUS ntstatus = NativeMethods.NtOpenProcess(
                        out IntPtr hProcess,
                        ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                        in objectAttributes,
                        in clientId);

                    if (ntstatus == Win32Consts.STATUS_SUCCESS)
                    {
                        info.ImageFilePath = Helpers.GetProcessImageFilePath(hProcess);
                        info.CommandLine = Helpers.GetProcessCommandLine(hProcess);
                        NativeMethods.NtClose(hProcess);
                    }

                    if (string.IsNullOrEmpty(info.ImageFilePath))
                        break;
                    else
                        info.ProcessName = Path.GetFileName(info.ImageFilePath);
                }

                bSuccess = Utilities.GetVerboseTokenInformation(
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

                if (bSuccess)
                {
                    Utilities.DumpVerboseTokenInformation(info, privs, groups, restrictedGroups, capabilities, acl);

                    if (hLinkedToken != IntPtr.Zero)
                    {
                        info.IsLinkedToken = true;
                        bSuccess = Utilities.GetVerboseTokenInformation(
                            hLinkedToken,
                            false,
                            out IntPtr _,
                            ref info,
                            out privs,
                            out groups,
                            out restrictedGroups,
                            out capabilities,
                            out acl);

                        if (bSuccess)
                            Utilities.DumpVerboseTokenInformation(info, privs, groups, restrictedGroups, capabilities, acl);

                        NativeMethods.NtClose(hLinkedToken);
                    }
                }

                if (info.SecurityAttributesBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(info.SecurityAttributesBuffer);
            } while (false);

            if (!bSuccess)
                Console.WriteLine("[-] Failed to dump token information.");

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }
    }
}
