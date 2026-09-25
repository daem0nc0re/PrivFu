using PrivMan.Library;
using System;

namespace PrivMan.Handler
{
    internal class Execute
    {
        internal static void Run(CommandLineParser options)
        {
            int pid;

            if (options.GetFlag("help"))
            {
                options.GetHelp();
                return;
            }
            else if (string.IsNullOrEmpty(options.GetValue("pid")))
            {
                Console.WriteLine("\n[!] -p option must be specified.\n");
                return;
            }

            try
            {
                pid = Convert.ToInt32(options.GetValue("pid"));
            }
            catch
            {
                Console.WriteLine("\n[!] Failed to parse PID.\n");
                return;
            }

            Console.WriteLine();

            if (options.GetFlag("get"))
                Modules.GetCurrentPrivileges(pid);
            else if (!string.IsNullOrEmpty(options.GetValue("disable")))
                Modules.DisablePrivileges(pid, options.GetValue("disable"));
            else if (!string.IsNullOrEmpty(options.GetValue("enable")))
                Modules.EnablePrivileges(pid, options.GetValue("enable"));
            else if (!string.IsNullOrEmpty(options.GetValue("filter")))
                Modules.FilterPrivileges(pid, options.GetValue("filter"));
            else if (!string.IsNullOrEmpty(options.GetValue("remove")))
                Modules.RemovePrivileges(pid, options.GetValue("remove"));
            else
                Console.WriteLine("[*] No options. Try -h option.");

            Console.WriteLine();
        }
    }
}
