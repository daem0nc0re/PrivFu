using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace PrivMan.Interop
{
    internal class TokenPrivileges
    {
        public static readonly Dictionary<string, LUID> Luids = new Dictionary<string, LUID>();
        public static readonly Dictionary<string, ulong> BitMasks = new Dictionary<string, ulong>();
        private static readonly string[] Names = new string[]
        {
            "SeCreateTokenPrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeLockMemoryPrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeMachineAccountPrivilege",
            "SeTcbPrivilege",
            "SeSecurityPrivilege",
            "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege",
            "SeSystemProfilePrivilege",
            "SeSystemtimePrivilege",
            "SeProfileSingleProcessPrivilege",
            "SeIncreaseBasePriorityPrivilege",
            "SeCreatePagefilePrivilege",
            "SeCreatePermanentPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeShutdownPrivilege",
            "SeDebugPrivilege",
            "SeAuditPrivilege",
            "SeSystemEnvironmentPrivilege",
            "SeChangeNotifyPrivilege",
            "SeRemoteShutdownPrivilege",
            "SeUndockPrivilege",
            "SeSyncAgentPrivilege",
            "SeEnableDelegationPrivilege",
            "SeManageVolumePrivilege",
            "SeImpersonatePrivilege",
            "SeCreateGlobalPrivilege",
            "SeTrustedCredManAccessPrivilege",
            "SeRelabelPrivilege",
            "SeIncreaseWorkingSetPrivilege",
            "SeTimeZonePrivilege",
            "SeCreateSymbolicLinkPrivilege",
            "SeDelegateSessionUserImpersonatePrivilege"
        };


        static TokenPrivileges()
        {
            foreach (var name in Names)
            {
                if (NativeMethods.LookupPrivilegeValue(null, name, out LUID luid))
                {
                    Luids[name] = luid;
                    BitMasks[name] = 1UL << (int)luid.LowPart;
                }
            }
        }


        internal static List<string> GetPrivilegeNames(string input)
        {
            var list = new List<string>();
            string[] patterns = input.Split(',');

            foreach (var name in Names)
            {
                foreach (var p in patterns)
                {
                    if (Regex.IsMatch(name, p.Trim(), RegexOptions.IgnoreCase))
                        list.Add(name);
                }
            }

            return list;
        }


        internal static string GetPrivilegeLuidTable(in List<string> names)
        {
            string lineFormat;
            var tableBuilder = new StringBuilder();
            var columnNames = new string[] { "Privilege Name", "LUID", "Bit Mask" };
            var columnWidths = new int[] { columnNames[0].Length, 16, 16 };

            try
            {
                foreach (var name in names)
                {
                    if (name.Length > columnWidths[0])
                        columnWidths[0] = name.Length;
                }

                lineFormat = string.Format("{{0, -{0}}} {{1, -{1}}} {{2}}\n",
                    columnWidths[0],
                    columnWidths[1]);
                tableBuilder.AppendFormat(lineFormat,
                    columnNames[0],
                    columnNames[1],
                    columnNames[2]);
                tableBuilder.AppendFormat(lineFormat,
                    new string('=', columnWidths[0]),
                    new string('=', columnWidths[1]),
                    new string('=', columnWidths[2]));

                foreach (var name in names)
                {
                    tableBuilder.AppendFormat(lineFormat,
                        name,
                        Luids[name].QuadPart.ToString("X16"),
                        BitMasks[name].ToString("X16"));
                }
            }
            catch (Exception ex)
            {
                tableBuilder.Clear();
                tableBuilder.AppendFormat("[!] {0}", ex.Message);
            }

            return tableBuilder.ToString();
        }


        internal static string GetPrivilegeStateTable(in SEP_TOKEN_PRIVILEGES privs)
        {
            string lineFormat;
            var states = new Dictionary<string, string>();
            var tableBuilder = new StringBuilder();
            var columnNames = new string[] { "Privilege Name", "State" };
            var columnWidths = new int[] { columnNames[0].Length, columnNames[1].Length };

            foreach (var name in Names)
            {
                if ((privs.Present & BitMasks[name]) != 0UL)
                {
                    var status = new StringBuilder();

                    if ((privs.EnabledByDefault & BitMasks[name]) != 0UL)
                        status.Append("Enabled By Default, ");

                    if ((privs.Enabled & BitMasks[name]) != 0UL)
                        status.Append("Enabled");
                    else
                        status.Append("Disabled");

                    states.Add(name, status.ToString());

                    if (name.Length > columnWidths[0])
                        columnWidths[0] = name.Length;

                    if (states[name].Length > columnWidths[1])
                        columnWidths[1] = states[name].Length;
                }
            }

            tableBuilder.AppendLine("PRIVILEGES INFORMATION");
            tableBuilder.AppendLine("----------------------\n");

            if (states.Count > 0)
            {
                lineFormat = string.Format("{{0, -{0}}} {{1}}\n", columnWidths[0]);
                tableBuilder.AppendFormat(lineFormat,
                    columnNames[0],
                    columnNames[1]);
                tableBuilder.AppendFormat(lineFormat,
                    new string('=', columnWidths[0]),
                    new string('=', columnWidths[1]));

                foreach (var entry in states)
                {
                    tableBuilder.AppendFormat(lineFormat, entry.Key, entry.Value);
                }
            }
            else
            {
                tableBuilder.AppendLine("No privileges.");
            }

            return tableBuilder.ToString();
        }
    }
}
