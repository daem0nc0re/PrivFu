using System;
using System.Collections.Generic;
using SwitchPriv.Library;

namespace SwitchPriv.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            int pid;
            int integrityIndex;
            string privilege;
            bool asSystem = options.GetFlag("system");

            if (options.GetFlag("help"))
            {
                options.GetHelp();
                return;
            }
            else if (options.GetFlag("list"))
            {
                Helpers.ListPrivilegeOptionValues();
                return;
            }

            if (!string.IsNullOrEmpty(options.GetValue("pid")))
            {
                try
                {
                    pid = Convert.ToInt32(options.GetValue("pid"));
                }
                catch
                {
                    options.GetHelp();
                    Console.WriteLine("[-] Failed to parse the specified --pid option value.\n");
                    return;
                }
            }
            else
            {
                pid = -1;
            }

            Console.WriteLine();
            
            if (options.GetFlag("get"))
            {
                Modules.GetPrivileges(pid, asSystem);
            }
            else if (!string.IsNullOrEmpty(options.GetValue("enable")))
            {
                privilege = options.GetValue("enable");

                if (string.Compare(privilege, "All", StringComparison.OrdinalIgnoreCase) == 0)
                    Modules.EnableAllPrivileges(pid, asSystem);
                else
                    Modules.EnableTokenPrivilege(pid, privilege, asSystem);
            }
            else if (!string.IsNullOrEmpty(options.GetValue("disable")))
            {
                privilege = options.GetValue("disable");

                if (string.Compare(privilege, "All", StringComparison.OrdinalIgnoreCase) == 0)
                    Modules.DisableAllPrivileges(pid, asSystem);
                else
                    Modules.DisableTokenPrivilege(pid, privilege, asSystem);
            }
            else if (!string.IsNullOrEmpty(options.GetValue("filter")))
            {
                privilege = options.GetValue("filter");

                if (privilege.Contains(","))
                {
                    var privs = privilege.Split(',');
                    var privsToRemain = new List<string>();

                    for (var idx = 0; idx < privs.Length; idx++)
                    {
                        if (!string.IsNullOrEmpty(privs[idx]))
                            privsToRemain.Add(privs[idx]);
                    }

                    Modules.FilterTokenPrivilege(pid, privsToRemain.ToArray(), asSystem);
                }
                else if (string.Compare(privilege, "All", StringComparison.OrdinalIgnoreCase) == 0)
                {
                    Console.WriteLine("[-] To remove all privileges, use -r option.");
                }
                else
                {
                    Modules.FilterTokenPrivilege(pid, new string[] { privilege }, asSystem);
                }
            }
            else if (!string.IsNullOrEmpty(options.GetValue("remove")))
            {
                privilege = options.GetValue("remove");

                if (string.Compare(privilege, "All", StringComparison.OrdinalIgnoreCase) == 0)
                    Modules.RemoveAllPrivileges(pid, asSystem);
                else
                    Modules.RemoveTokenPrivilege(pid, privilege, asSystem);
            }
            else if (!string.IsNullOrEmpty(options.GetValue("search")))
            {
                privilege = options.GetValue("search");

                if (string.Compare(privilege, "All", StringComparison.OrdinalIgnoreCase) == 0)
                    Console.WriteLine("[!] Specifies only one privilege at a time for this option.");
                else
                    Modules.SearchPrivilegedProcess(privilege, asSystem);
            }
            else if (!string.IsNullOrEmpty(options.GetValue("integrity")))
            {
                try
                {
                    integrityIndex = Convert.ToInt32(options.GetValue("integrity"));
                }
                catch
                {
                    options.GetHelp();
                    Console.WriteLine("[-] Failed to parse the specified --integrity option value.");

                    return;
                }

                Modules.SetIntegrityLevel(pid, integrityIndex, options.GetFlag("system"));
            }
            else
            {
                Console.WriteLine("[-] No options.");
            }

            Console.WriteLine();
        }
    }
}
