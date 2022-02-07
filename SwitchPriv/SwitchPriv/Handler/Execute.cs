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
            int integrityIndex;
            StringComparison opt = StringComparison.OrdinalIgnoreCase;

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
                pid = 0;
            }
            
            if (options.GetFlag("get"))
            {
                Modules.GetPrivileges(pid, options.GetFlag("system"));
            }
            else if (!string.IsNullOrEmpty(options.GetValue("enable")))
            {
                if (string.Compare(options.GetValue("enable"), "All", opt) == 0)
                {
                    Modules.EnableAllPrivileges(pid, options.GetFlag("system"));
                }
                else
                {
                    priv = Helpers.GetFullPrivilegeName(options.GetValue("enable"));

                    if (priv == null)
                    {
                        options.GetHelp();
                        Console.WriteLine("[-] Failed to specify requested token privilege.\n");

                        return;
                    }

                    Modules.EnableTokenPrivilege(pid, priv, options.GetFlag("system"));
                }
            }
            else if (!string.IsNullOrEmpty(options.GetValue("disable")))
            {
                if (string.Compare(options.GetValue("disable"), "All", opt) == 0)
                {
                    Modules.DisableAllPrivileges(pid, options.GetFlag("system"));
                }
                else
                {
                    priv = Helpers.GetFullPrivilegeName(options.GetValue("disable"));

                    if (string.IsNullOrEmpty(priv))
                    {
                        options.GetHelp();
                        Console.WriteLine("[-] Failed to specify the requested token privilege.\n");

                        return;
                    }

                    Modules.DisableTokenPrivilege(pid, priv, options.GetFlag("system"));
                }
            }
            else if (!string.IsNullOrEmpty(options.GetValue("remove")))
            {
                if (string.Compare(options.GetValue("remove"), "All", opt) == 0)
                {
                    Modules.RemoveAllPrivileges(pid, options.GetFlag("system"));
                }
                else
                {
                    priv = Helpers.GetFullPrivilegeName(options.GetValue("remove"));

                    if (string.IsNullOrEmpty(priv))
                    {
                        options.GetHelp();
                        Console.WriteLine("[-] Failed to the specify requested token privilege.\n");

                        return;
                    }

                    Modules.RemoveTokenPrivilege(pid, priv, options.GetFlag("system"));
                }
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
                    Console.WriteLine("[-] Failed to parse the specified --integrity option value.\n");

                    return;
                }

                Modules.SetIntegrityLevel(pid, integrityIndex, options.GetFlag("system"));
            }
            else
            {
                options.GetHelp();
            }
        }
    }
}
