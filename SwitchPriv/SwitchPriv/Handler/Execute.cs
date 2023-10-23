using System;
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

                if (Helpers.CompareIgnoreCase(privilege, "All"))
                    Modules.EnableAllPrivileges(pid, asSystem);
                else
                    Modules.EnableTokenPrivilege(pid, privilege, asSystem);
            }
            else if (!string.IsNullOrEmpty(options.GetValue("disable")))
            {
                privilege = options.GetValue("disable");

                if (Helpers.CompareIgnoreCase(privilege, "All"))
                    Modules.DisableAllPrivileges(pid, asSystem);
                else
                    Modules.DisableTokenPrivilege(pid, privilege, asSystem);
            }
            else if (!string.IsNullOrEmpty(options.GetValue("filter")))
            {
                privilege = options.GetValue("filter");

                if (Helpers.CompareIgnoreCase(privilege, "All"))
                    Console.WriteLine("[!] Specifies only one privilege at a time for this option.");
                else
                    Modules.FilterTokenPrivilege(pid, privilege, asSystem);
            }
            else if (!string.IsNullOrEmpty(options.GetValue("remove")))
            {
                privilege = options.GetValue("remove");

                if (Helpers.CompareIgnoreCase(privilege, "All"))
                    Modules.RemoveAllPrivileges(pid, asSystem);
                else
                    Modules.RemoveTokenPrivilege(pid, privilege, asSystem);
            }
            else if (!string.IsNullOrEmpty(options.GetValue("search")))
            {
                privilege = options.GetValue("search");

                if (Helpers.CompareIgnoreCase(privilege, "All"))
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
