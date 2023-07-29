using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using TokenDump.Interop;

namespace TokenDump.Library
{
    internal class Utilities
    {
        public static void DumpBriefHandleInformation(
            List<BriefTokenInformation> info,
            string accountFilter,
            out int nResultsCount)
        {
            string format;
            var titles = new string[] {
                "Handle",
                "Token User",
                "Integrity",
                "Restricted",
                "AppContainer",
                "Token Type",
                "Impersonation Level"
            };
            var width = new int[titles.Length];
            var outputBuilder = new StringBuilder();
            var filteredInfo = new List<BriefTokenInformation>();
            nResultsCount = 0;

            for (var idx = 0; idx < titles.Length; idx++)
                width[idx] = titles[idx].Length;

            if (info.Count == 0)
                return;

            if (!string.IsNullOrEmpty(accountFilter))
            {
                var comparison = StringComparison.OrdinalIgnoreCase;

                foreach (var entry in info)
                {
                    if (entry.TokenUserName.IndexOf(accountFilter, comparison) >= 0)
                        filteredInfo.Add(entry);
                }
            }
            else
            {
                filteredInfo.AddRange(info);
            }

            if (filteredInfo.Count == 0)
                return;

            nResultsCount = filteredInfo.Count;

            foreach (var entry in filteredInfo)
            {
                if (entry.Handle.ToString("X").Length + 2 > width[0])
                    width[0] = entry.Handle.ToString("X").Length + 2;

                if (entry.TokenUserName.Length > width[1])
                    width[1] = entry.TokenUserName.Length;

                if (entry.Integrity.Length > width[2])
                    width[2] = entry.Integrity.Length;

                if (entry.TokenType.ToString().Length > width[5])
                    width[5] = entry.TokenType.ToString().Length;

                if (entry.ImpersonationLevel.ToString().Length > width[6])
                    width[6] = entry.ImpersonationLevel.ToString().Length;
            }

            format = string.Format(
                "{{0,{0}}} {{1,-{1}}} {{2,-{2}}} {{3,-{3}}} {{4,-{4}}} {{5,-{5}}} {{6,-{6}}}\n",
                width[0], width[1], width[2], width[3], width[4], width[5], width[6]);

            outputBuilder.AppendFormat(
                "\n[Token Handle(s) - {0} (PID: {1})]\n\n",
                info[0].ProcessName, info[0].ProcessId);
            outputBuilder.AppendFormat(
                format,
                titles[0], titles[1], titles[2], titles[3], titles[4], titles[5], titles[6]);
            outputBuilder.AppendFormat(
                format,
                new string('=', width[0]),
                new string('=', width[1]),
                new string('=', width[2]),
                new string('=', width[3]),
                new string('=', width[4]),
                new string('=', width[5]),
                new string('=', width[6]));

            foreach (var entry in filteredInfo)
            {
                outputBuilder.AppendFormat(
                    format,
                    string.Format("0x{0}", entry.Handle.ToString("X")),
                    entry.TokenUserName,
                    entry.Integrity,
                    entry.IsRestricted.ToString(),
                    entry.IsAppContainer.ToString(),
                    entry.TokenType.ToString(),
                    entry.ImpersonationLevel.ToString());
            }

            Console.WriteLine(outputBuilder.ToString());
        }


        public static void DumpBriefProcessInformation(
            List<BriefTokenInformation> info,
            string accountFilter,
            out int nResultsCount)
        {
            string format;
            var titles = new string[] {
                "PID",
                "Process Name",
                "Token User",
                "Integrity",
                "Restricted",
                "AppContainer"
            };
            var width = new int[titles.Length];
            var outputBuilder = new StringBuilder();
            var filteredInfo = new List<BriefTokenInformation>();
            nResultsCount = 0;

            for (var idx = 0; idx < titles.Length; idx++)
                width[idx] = titles[idx].Length;

            if (info.Count == 0)
                return;

            if (!string.IsNullOrEmpty(accountFilter))
            {
                var comparison = StringComparison.OrdinalIgnoreCase;

                foreach (var entry in info)
                {
                    if (entry.TokenUserName.IndexOf(accountFilter, comparison) >= 0)
                        filteredInfo.Add(entry);
                }
            }
            else
            {
                filteredInfo.AddRange(info);
            }

            if (filteredInfo.Count == 0)
                return;

            nResultsCount = filteredInfo.Count;

            foreach (var entry in filteredInfo)
            {
                if (entry.ProcessId.ToString().Length > width[0])
                    width[0] = entry.ProcessId.ToString().Length;

                if (entry.ProcessName.Length > width[1])
                    width[1] = entry.ProcessName.Length;

                if (entry.TokenUserName.Length > width[2])
                    width[2] = entry.TokenUserName.Length;

                if (entry.Integrity.Length > width[3])
                    width[3] = entry.Integrity.Length;
            }

            format = string.Format(
                "{{0,{0}}} {{1,-{1}}} {{2,-{2}}} {{3,-{3}}} {{4,-{4}}} {{5,-{5}}}\n",
                width[0], width[1], width[2], width[3], width[4], width[5]);

            outputBuilder.Append("\n");
            outputBuilder.AppendFormat(
                format,
                titles[0], titles[1], titles[2], titles[3], titles[4], titles[5]);
            outputBuilder.AppendFormat(
                format,
                new string('=', width[0]),
                new string('=', width[1]),
                new string('=', width[2]),
                new string('=', width[3]),
                new string('=', width[4]),
                new string('=', width[5]));

            foreach (var entry in filteredInfo)
            {
                outputBuilder.AppendFormat(
                    format,
                    entry.ProcessId.ToString(),
                    entry.ProcessName,
                    entry.TokenUserName,
                    entry.Integrity,
                    entry.IsRestricted.ToString(),
                    entry.IsAppContainer.ToString());
            }

            Console.WriteLine(outputBuilder.ToString());
        }


        public static void DumpBriefThreadInformation(
            List<BriefTokenInformation> info,
            string accountFilter,
            out int nResultsCount)
        {
            string format;
            var titles = new string[] {
                "PID",
                "TID",
                "Process Name",
                "Token User",
                "Integrity",
                "Impersonation Level"
            };
            var width = new int[titles.Length];
            var outputBuilder = new StringBuilder();
            var filteredInfo = new List<BriefTokenInformation>();
            nResultsCount = 0;

            for (var idx = 0; idx < titles.Length; idx++)
                width[idx] = titles[idx].Length;

            if (info.Count == 0)
                return;

            if (!string.IsNullOrEmpty(accountFilter))
            {
                var comparison = StringComparison.OrdinalIgnoreCase;

                foreach (var entry in info)
                {
                    if (entry.TokenUserName.IndexOf(accountFilter, comparison) >= 0)
                        filteredInfo.Add(entry);
                }
            }
            else
            {
                filteredInfo.AddRange(info);
            }

            if (filteredInfo.Count == 0)
                return;

            nResultsCount = filteredInfo.Count;

            foreach (var entry in filteredInfo)
            {
                if (entry.ProcessId.ToString().Length > width[0])
                    width[0] = entry.ProcessId.ToString().Length;

                if (entry.ThreadId.ToString().Length > width[1])
                    width[1] = entry.ThreadId.ToString().Length;

                if (entry.ProcessName.Length > width[2])
                    width[2] = entry.ProcessName.Length;

                if (entry.TokenUserName.Length > width[3])
                    width[3] = entry.TokenUserName.Length;

                if (entry.Integrity.ToString().Length > width[4])
                    width[4] = entry.Integrity.ToString().Length;

                if (entry.ImpersonationLevel.ToString().Length > width[5])
                    width[5] = entry.ImpersonationLevel.ToString().Length;
            }

            format = string.Format(
                "{{0,{0}}} {{1,{1}}} {{2,-{2}}} {{3,-{3}}} {{4,-{4}}} {{5,-{5}}}\n",
                width[0], width[1], width[2], width[3], width[4], width[5]);

            outputBuilder.Append("\n");
            outputBuilder.AppendFormat(
                format,
                titles[0], titles[1], titles[2], titles[3], titles[4], titles[5]);
            outputBuilder.AppendFormat(
                format,
                new string('=', width[0]),
                new string('=', width[1]),
                new string('=', width[2]),
                new string('=', width[3]),
                new string('=', width[4]),
                new string('=', width[5]));

            foreach (var entry in filteredInfo)
            {
                outputBuilder.AppendFormat(
                    format,
                    entry.ProcessId.ToString(),
                    entry.ThreadId.ToString(),
                    entry.ProcessName,
                    entry.TokenUserName,
                    entry.Integrity,
                    entry.ImpersonationLevel.ToString());
            }

            Console.WriteLine(outputBuilder.ToString());
        }


        public static void DumpVerboseTokenInformation(
            VerboseTokenInformation info,
            Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> privs,
            Dictionary<string, SE_GROUP_ATTRIBUTES> groups,
            List<AceInformation> acl)
        {
            var outputBuilder = new StringBuilder();

            outputBuilder.Append("\n");

            if (info.Handle == IntPtr.Zero)
            {
                if (info.IsLinkedToken)
                {
                    outputBuilder.AppendFormat(
                        "[Linked Token Information for {0} (PID: {1})]\n\n",
                        info.ProcessName, info.ProcessId);
                }
                else if (info.ThreadId != 0)
                {
                    outputBuilder.AppendFormat(
                        "[Token Information for {0} (PID: {1}, TID: {0})]\n\n",
                        info.ProcessName, info.ProcessId, info.ThreadId);
                }
                else
                {
                    outputBuilder.AppendFormat(
                        "[Token Information for {0} (PID: {1})]\n\n",
                        info.ProcessName, info.ProcessId);
                }
            }
            else
            {
                if (info.IsLinkedToken)
                {
                    outputBuilder.AppendFormat(
                        "[Linked Token Information for Handle 0x{0} of {1} (PID: {2})]\n\n",
                        info.Handle.ToString("X"), info.ProcessName, info.ProcessId);
                }
                else
                {
                    outputBuilder.AppendFormat(
                        "[Token Information for Handle 0x{0} of {1} (PID: {2})]\n\n",
                        info.Handle.ToString("X"), info.ProcessName, info.ProcessId);
                }
            }

            if ((info.ThreadId == 0) && (info.Handle == IntPtr.Zero) && !info.IsLinkedToken)
            {
                var imageFilePath = Helpers.ConvertDevicePathToDriveLetter(info.ImageFilePath);

                outputBuilder.AppendFormat("ImageFilePath       : {0}\n", string.IsNullOrEmpty(imageFilePath) ? "N/A" : imageFilePath);
                outputBuilder.AppendFormat("CommandLine         : {0}\n", info.CommandLine);
            }

            outputBuilder.AppendFormat("Token User          : {0} (SID: {1})\n", info.TokenUserName, info.TokenUserSid);
            outputBuilder.AppendFormat("Token Owner         : {0} (SID: {1})\n", info.TokenOwnerName, info.TokenOwnerSid);
            outputBuilder.AppendFormat("Primary Group       : {0} (SID: {1})\n", info.TokenPrimaryGroupName, info.TokenPrimaryGroupSid);
            outputBuilder.AppendFormat("Token Type          : {0}\n", info.TokenStatistics.TokenType.ToString());
            outputBuilder.AppendFormat("Impersonation Level : {0}\n", info.TokenStatistics.ImpersonationLevel.ToString());
            outputBuilder.AppendFormat("Token ID            : 0x{0}\n", info.TokenStatistics.TokenId.ToInt64().ToString("X16"));
            outputBuilder.AppendFormat("Authentication ID   : 0x{0}\n", info.TokenStatistics.AuthenticationId.ToInt64().ToString("X16"));
            outputBuilder.AppendFormat("Original ID         : 0x{0}\n", info.TokenOrigin.OriginatingLogonSession.ToInt64().ToString("X16"));
            outputBuilder.AppendFormat("Modified ID         : 0x{0}\n", info.TokenStatistics.ModifiedId.ToInt64().ToString("X16"));
            outputBuilder.AppendFormat("Integrity Level     : {0}\n", info.Integrity.ToString());
            outputBuilder.AppendFormat("Session ID          : {0}\n", info.SessionId);
            outputBuilder.AppendFormat("Elevation Type      : {0}\n", info.ElevationType.ToString());
            outputBuilder.AppendFormat("Elevated            : {0}\n", info.IsElevated.ToString());
            outputBuilder.AppendFormat("Restricted          : {0}\n", info.IsRestricted.ToString());
            outputBuilder.AppendFormat("AppContainer        : {0}\n", info.IsAppContainer.ToString());

            if (info.IsAppContainer)
            {
                outputBuilder.AppendFormat(
                    "AppContainer Name   : {0}\n",
                    string.IsNullOrEmpty(info.AppContainerName) ? "N/A" : info.AppContainerName);
                outputBuilder.AppendFormat(
                    "AppContainer SID    : {0}\n",
                    string.IsNullOrEmpty(info.AppContainerSid) ? "N/A" : info.AppContainerSid);
            }

            if (!info.IsLinkedToken)
                outputBuilder.AppendFormat("Has Linked Token    : {0}\n", info.HasLinkedToken.ToString());

            if (BitConverter.ToInt64(info.TokenSource.SourceName, 0) == 0L)
            {
                outputBuilder.AppendFormat("Token Source        : N/A\n");
                outputBuilder.AppendFormat("Token Source ID     : N/A\n");
            }
            else
            {
                outputBuilder.AppendFormat("Token Source        : {0}\n", Encoding.ASCII.GetString(info.TokenSource.SourceName));
                outputBuilder.AppendFormat("Token Source ID     : 0x{0}\n", info.TokenSource.SourceIdentifier.ToInt64().ToString("X16"));
            }

            outputBuilder.Append(ParseTokenPrivilegesTableToString(privs));
            outputBuilder.Append(ParseTokenGroupsTableToString(groups));
            outputBuilder.Append(ParseTokenDaclTableToString(acl));

            Console.WriteLine(outputBuilder.ToString());
        }


        public static bool GetBriefThreadTokenInformation(
            int pid,
            List<SYSTEM_HANDLE_TABLE_ENTRY_INFO> handles,
            out List<BriefTokenInformation> info)
        {
            IntPtr hProcess = NativeMethods.OpenProcess(
                ACCESS_MASK.PROCESS_DUP_HANDLE | ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid);
            info = new List<BriefTokenInformation>();

            if (hProcess != IntPtr.Zero)
            {
                var uniqueThreads = new List<int>();

                foreach (var entry in handles)
                {
                    var ntstatus = NativeMethods.NtDuplicateObject(
                        hProcess,
                        new IntPtr(entry.HandleValue),
                        new IntPtr(-1),
                        out IntPtr hDupObject,
                        ACCESS_MASK.THREAD_QUERY_LIMITED_INFORMATION,
                        0,
                        0);

                    if (ntstatus == Win32Consts.STATUS_SUCCESS)
                    {
                        var data = new BriefTokenInformation();
                        bool status = Helpers.GetThreadBasicInformation(
                            hDupObject,
                            out THREAD_BASIC_INFORMATION tbi);
                        data.ImageFilePath = Helpers.GetProcessImageFilePath(hProcess);
                        data.ProcessId = tbi.ClientId.UniqueProcess.ToInt32();
                        data.ThreadId = tbi.ClientId.UniqueThread.ToInt32();

                        if (string.IsNullOrEmpty(data.ImageFilePath))
                        {
                            NativeMethods.NtClose(hDupObject);
                            continue;
                        }
                        else
                        {
                            data.ProcessName = Path.GetFileName(data.ImageFilePath);
                        }

                        if (status && !uniqueThreads.Contains(data.ThreadId) && (data.ProcessId == pid))
                        {
                            uniqueThreads.Add(data.ThreadId);

                            status = NativeMethods.OpenThreadToken(
                                hDupObject,
                                ACCESS_MASK.TOKEN_QUERY,
                                false,
                                out IntPtr hToken);
                            NativeMethods.NtClose(hDupObject);

                            if (status)
                            {
                                var sid = Helpers.GetTokenUserSid(hToken);
                                data.Integrity = Helpers.GetTokenIntegrityLevel(hToken);
                                Helpers.ConvertStringSidToAccountName(sid, out data.TokenUserName, out SID_NAME_USE _);
                                Helpers.GetTokenStatistics(hToken, out TOKEN_STATISTICS stats);
                                Helpers.IsTokenRestricted(hToken, out data.IsRestricted);
                                Helpers.IsTokenAppContainer(hToken, out data.IsAppContainer);
                                data.TokenType = stats.TokenType;
                                data.ImpersonationLevel = stats.ImpersonationLevel;

                                info.Add(data);
                            }
                        }
                    }
                }

                NativeMethods.NtClose(hProcess);
            }

            return (info.Count > 0);
        }


        public static bool GetBriefTokenInformationFromHandle(
            int pid,
            List<SYSTEM_HANDLE_TABLE_ENTRY_INFO> handles,
            out List<BriefTokenInformation> info)
        {
            IntPtr hProcess = NativeMethods.OpenProcess(
                ACCESS_MASK.PROCESS_DUP_HANDLE | ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid);
            info = new List<BriefTokenInformation>();

            if (hProcess != IntPtr.Zero)
            {
                foreach (var entry in handles)
                {
                    var ntstatus = NativeMethods.NtDuplicateObject(
                        hProcess,
                        new IntPtr(entry.HandleValue),
                        new IntPtr(-1),
                        out IntPtr hDupObject,
                        ACCESS_MASK.TOKEN_QUERY,
                        0,
                        0);

                    if (ntstatus == Win32Consts.STATUS_SUCCESS)
                    {
                        var data = new BriefTokenInformation();
                        var sid = Helpers.GetTokenUserSid(hDupObject);
                        data.ImageFilePath = Helpers.GetProcessImageFilePath(hProcess);

                        if (string.IsNullOrEmpty(sid) || string.IsNullOrEmpty(data.ImageFilePath))
                        {
                            NativeMethods.NtClose(hDupObject);
                            continue;
                        }
                        else
                        {
                            data.ProcessName = Path.GetFileName(data.ImageFilePath);
                        }

                        data.ProcessId = pid;
                        data.Handle = new IntPtr(entry.HandleValue);
                        data.Integrity = Helpers.GetTokenIntegrityLevel(hDupObject);
                        Helpers.ConvertStringSidToAccountName(sid, out data.TokenUserName, out SID_NAME_USE _);
                        Helpers.GetTokenStatistics(hDupObject, out TOKEN_STATISTICS stats);
                        Helpers.IsTokenRestricted(hDupObject, out data.IsRestricted);
                        Helpers.IsTokenAppContainer(hDupObject, out data.IsAppContainer);
                        data.TokenType = stats.TokenType;
                        data.ImpersonationLevel = stats.ImpersonationLevel;

                        NativeMethods.NtClose(hDupObject);
                        info.Add(data);
                    }
                }

                NativeMethods.NtClose(hProcess);
            }

            return (info.Count > 0);
        }


        public static bool GetBriefTokenInformationFromProcess(
            int pid,
            out BriefTokenInformation info)
        {
            IntPtr hProcess = NativeMethods.OpenProcess(
                ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid);
            var status = false;
            info = new BriefTokenInformation { ProcessId = pid };

            if (hProcess != IntPtr.Zero)
            {
                status = NativeMethods.OpenProcessToken(
                    hProcess,
                    ACCESS_MASK.TOKEN_QUERY,
                    out IntPtr hToken);

                if (status)
                {
                    var tokenUserSid = Helpers.GetTokenUserSid(hToken);

                    if (!string.IsNullOrEmpty(tokenUserSid))
                    {
                        Helpers.ConvertStringSidToAccountName(tokenUserSid, out string account, out SID_NAME_USE _);
                        info.TokenUserName = account;
                    }

                    info.Integrity = Helpers.GetTokenIntegrityLevel(hToken);
                    info.ImageFilePath = Helpers.GetProcessImageFilePath(hProcess);
                    Helpers.IsTokenRestricted(hToken, out info.IsRestricted);
                    Helpers.IsTokenAppContainer(hToken, out info.IsAppContainer);

                    if (string.IsNullOrEmpty(info.ImageFilePath))
                    {
                        info = new BriefTokenInformation();
                        status = false;
                    }
                    else
                    {
                        info.ProcessName = Path.GetFileName(info.ImageFilePath);
                    }

                    NativeMethods.NtClose(hToken);
                }

                NativeMethods.NtClose(hProcess);
            }

            return status;
        }


        public static bool GetVerboseTokenInformation(
            IntPtr hToken,
            bool isLinkedToken,
            out IntPtr hLinkedToken,
            ref VerboseTokenInformation info,
            out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> privs,
            out Dictionary<string, SE_GROUP_ATTRIBUTES> groups,
            out List<AceInformation> acl)
        {
            var status = false;
            hLinkedToken = IntPtr.Zero;

            do
            {
                Helpers.GetTokenPrivileges(hToken, out privs);
                Helpers.GetTokenGroups(hToken, out groups);
                Helpers.GetTokenDefaultDacl(hToken, out acl);
                info.SessionId = Helpers.GetTokenSessionId(hToken);

                if (info.SessionId == -1)
                    break;

                info.Integrity = Helpers.GetTokenIntegrityLevel(hToken);

                if (string.IsNullOrEmpty(info.Integrity))
                    break;

                info.TokenUserSid = Helpers.GetTokenUserSid(hToken);

                if (string.IsNullOrEmpty(info.TokenUserSid))
                    break;

                status = Helpers.ConvertStringSidToAccountName(
                    info.TokenUserSid,
                    out info.TokenUserName,
                    out SID_NAME_USE _);

                if (!status)
                    break;

                info.TokenOwnerSid = Helpers.GetTokenOwnerSid(hToken);

                if (string.IsNullOrEmpty(info.TokenOwnerSid))
                    break;

                status = Helpers.ConvertStringSidToAccountName(
                    info.TokenOwnerSid,
                    out info.TokenOwnerName,
                    out SID_NAME_USE _);

                if (!status)
                    break;

                info.TokenPrimaryGroupSid = Helpers.GetTokenPrimaryGroupSid(hToken);

                if (string.IsNullOrEmpty(info.TokenPrimaryGroupSid))
                    break;

                status = Helpers.ConvertStringSidToAccountName(
                    info.TokenPrimaryGroupSid,
                    out info.TokenPrimaryGroupName,
                    out SID_NAME_USE _);

                if (!status)
                    break;

                if (!Helpers.GetTokenElevationType(hToken, out info.ElevationType))
                    break;

                if (!Helpers.GetTokenOrigin(hToken, out info.TokenOrigin))
                    break;

                Helpers.GetTokenSource(hToken, out info.TokenSource);

                if (!Helpers.GetTokenStatistics(hToken, out info.TokenStatistics))
                    break;

                if (!Helpers.IsTokenAppContainer(hToken, out info.IsAppContainer))
                    break;

                if (!Helpers.IsTokenElevated(hToken, out info.IsElevated))
                    break;

                if (!Helpers.IsTokenRestricted(hToken, out info.IsRestricted))
                    break;

                if (info.IsAppContainer)
                {
                    Helpers.GetTokenAppContainerSid(hToken, out info.AppContainerSid, out info.AppContainerName);
                }

                if (isLinkedToken)
                {
                    hLinkedToken = IntPtr.Zero;
                }
                else
                {
                    status = Helpers.GetTokenLinkedToken(
                        hToken,
                        out hLinkedToken,
                        out info.HasLinkedToken);
                }
            } while (false);

            if (!status)
                info = new VerboseTokenInformation();

            return status;
        }


        private static string ParseTokenDaclTableToString(List<AceInformation> acl)
        {
            var titles = new string[] { "Account Name", "Access", "Flags", "Type" };
            var width = new int[titles.Length];
            var tableBuilder = new StringBuilder();
            var indent = new string(' ', 4);

            for (var idx = 0; idx < titles.Length; idx++)
                width[idx] = titles[idx].Length;

            foreach (var ace in acl)
            {
                if (ace.AccountName.Length > width[0])
                    width[0] = ace.AccountName.Length;

                if (((TokenAccessFlags)ace.AccessMask).ToString().Length > width[1])
                    width[1] = ((TokenAccessFlags)ace.AccessMask).ToString().Length;

                if (ace.Flags.ToString().Length > width[2])
                    width[2] = ace.Flags.ToString().Length;

                if (ace.Type.ToString().Length > width[3])
                    width[3] = ace.Type.ToString().Length;
            }

            tableBuilder.Append("\n");
            tableBuilder.AppendFormat("{0}DACL INFORMATION\n", indent);
            tableBuilder.AppendFormat("{0}----------------\n\n", indent);

            if (acl.Count == 0)
            {
                tableBuilder.AppendFormat("{0}No entries.\n", indent);
            }
            else
            {
                var lineFormat = string.Format(
                    "{{0}}{{1,-{0}}} {{2,-{1}}} {{3,-{2}}} {{4,-{3}}}\n",
                    width[0], width[1], width[2], width[3]);

                tableBuilder.AppendFormat(lineFormat, indent, titles[0], titles[1], titles[2], titles[3]);
                tableBuilder.AppendFormat(
                    lineFormat,
                    indent,
                    new string('=', width[0]),
                    new string('=', width[1]),
                    new string('=', width[2]),
                    new string('=', width[3]));

                foreach (var ace in acl)
                {
                    tableBuilder.AppendFormat(
                        lineFormat,
                        indent,
                        ace.AccountName,
                        ((TokenAccessFlags)ace.AccessMask).ToString(),
                        ace.Flags.ToString(),
                        ace.Type.ToString());
                }
            }

            tableBuilder.Append("\n");

            return tableBuilder.ToString();
        }


        private static string ParseTokenGroupsTableToString(
            Dictionary<string, SE_GROUP_ATTRIBUTES> groups)
        {
            var titles = new string[] { "Group Name", "Attributes" };
            var width = new int[titles.Length];
            var tableBuilder = new StringBuilder();
            var tableData = new Dictionary<string, string>();
            var indent = new string(' ', 4);

            for (var idx = 0; idx < titles.Length; idx++)
                width[idx] = titles[idx].Length;

            foreach (var entry in groups)
            {
                Helpers.ConvertStringSidToAccountName(entry.Key, out string account, out SID_NAME_USE _);

                if (string.IsNullOrEmpty(account))
                    continue;

                tableData.Add(account, entry.Value.ToString());

                if (account.Length > width[0])
                    width[0] = account.Length;

                if (entry.Value.ToString().Length > width[1])
                    width[1] = entry.Value.ToString().Length;
            }

            tableBuilder.Append("\n");
            tableBuilder.AppendFormat("{0}GROUP INFORMATION\n", indent);
            tableBuilder.AppendFormat("{0}-----------------\n\n", indent);

            if (tableData.Count == 0)
            {
                tableBuilder.AppendFormat("{0}No groups.\n", indent);
            }
            else
            {
                var lineFormat = string.Format("{{0}}{{1,-{0}}} {{2,-{1}}}\n", width[0], width[1]);
                tableBuilder.AppendFormat(lineFormat, indent, titles[0], titles[1]);
                tableBuilder.AppendFormat(lineFormat, indent, new string('=', width[0]), new string('=', width[1]));

                foreach (var entry in tableData)
                    tableBuilder.AppendFormat(lineFormat, indent, entry.Key, entry.Value);
            }

            tableBuilder.Append("\n");

            return tableBuilder.ToString();
        }


        private static string ParseTokenPrivilegesTableToString(
            Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> privs)
        {
            var titles = new string[] { "Privilege Name", "State" };
            var width = new int[titles.Length];
            var tableBuilder = new StringBuilder();
            var tableData = new Dictionary<string, string>();
            var indent = new string(' ', 4);

            for (var idx = 0; idx < titles.Length; idx++)
                width[idx] = titles[idx].Length;

            foreach (var entry in privs)
            {
                var state = entry.Value.ToString();

                if (entry.Value == SE_PRIVILEGE_ATTRIBUTES.EnabledByDefault)
                {
                    state = "EnabledByDefault, Disabled";
                }

                tableData.Add(entry.Key, state);

                if (entry.Key.Length > width[0])
                    width[0] = entry.Key.Length;

                if (state.Length > width[1])
                    width[1] = state.Length;
            }

            tableBuilder.Append("\n");
            tableBuilder.AppendFormat("{0}PRIVILEGES INFORMATION\n", indent);
            tableBuilder.AppendFormat("{0}----------------------\n\n", indent);

            if (tableData.Count == 0)
            {
                tableBuilder.AppendFormat("{0}No privileges.\n", indent);
            }
            else
            {
                var lineFormat = string.Format("{{0}}{{1,-{0}}} {{2,-{1}}}\n", width[0], width[1]);
                tableBuilder.AppendFormat(lineFormat, indent, titles[0], titles[1]);
                tableBuilder.AppendFormat(lineFormat, indent, new string('=', width[0]), new string('=', width[1]));

                foreach (var entry in tableData)
                    tableBuilder.AppendFormat(lineFormat, indent, entry.Key, entry.Value);
            }

            tableBuilder.Append("\n");

            return tableBuilder.ToString();
        }
    }
}
