using System;
using SwitchPriv.Library;

namespace SwitchPriv.Handler
{
    class Execute
    {
        public static void Run(CommandLineParser options)
        {
            int pid;
            string priv;
            StringComparison opt = StringComparison.OrdinalIgnoreCase;

            if (options.GetValue("pid") != string.Empty)
            {
                try
                {
                    pid = Convert.ToInt32(options.GetValue("pid"));
                }
                catch
                {
                    options.GetHelp();
                    Console.WriteLine("[-] Failed to parse specified --pid option value.\n");
                    return;
                }
            }
            else
            {
                pid = 0;
            }

            if (options.GetFlag("help"))
            {
                options.GetHelp();
            }
            else if (options.GetFlag("list"))
            {
                Helpers.ListPrivilegeOptionValues();
            }
            else if (options.GetFlag("get"))
            {
                Modules.GetPrivileges(pid);
            }
            else if (options.GetValue("enable") != string.Empty)
            {
                if (string.Compare(options.GetValue("enable"), "All", opt) == 0)
                {
                    Modules.EnableAllPrivileges(pid);
                }
                else
                {
                    priv = Helpers.GetFullPrivilegeName(options.GetValue("enable"));

                    if (priv == string.Empty)
                    {
                        options.GetHelp();
                        Console.WriteLine("[-] Failed to specify requested token privilege.\n");
                        return;
                    }

                    Modules.EnableTokenPrivilege(pid, priv);
                }
            }
            else if (options.GetValue("disable") != string.Empty)
            {
                if (string.Compare(options.GetValue("disable"), "All", opt) == 0)
                {
                    Modules.DisableAllPrivileges(pid);
                }
                else
                {
                    priv = Helpers.GetFullPrivilegeName(options.GetValue("disable"));

                    if (priv == string.Empty)
                    {
                        options.GetHelp();
                        Console.WriteLine("[-] Failed to specify requested token privilege.\n");
                        return;
                    }

                    Modules.DisableTokenPrivilege(pid, priv);
                }
            }
            else
            {
                options.GetHelp();
            }
        }
    }
}
