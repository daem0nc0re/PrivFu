using System;
using TrustExec.Library;

namespace TrustExec.Handler
{
    internal class Execute
    {
        public static void ExecCommand(CommandLineParser options)
        {
            int domainRid;
            int techId;

            if (options.GetFlag("help"))
            {
                options.GetHelp();
                Console.WriteLine("Available Technique IDs:\n");
                Console.WriteLine("\t+ 0 - Leverages SeCreateTokenPrivilege. Uses only --shell flag, --full flag and --command option.");
                Console.WriteLine("\t+ 1 - Leverages virtual logon. This technique creates virtual domain and account as a side effect.");
                Console.WriteLine();

                return;
            }

            try
            {
                techId = Convert.ToInt32(options.GetValue("technique"));
            }
            catch
            {
                Console.WriteLine("\n[-] Failed to parse technique ID.\n");

                return;
            }

            try
            {
                domainRid = Convert.ToInt32(options.GetValue("id"));
            }
            catch
            {
                Console.WriteLine("\n[-] Failed to parse RID for virtual domain.\n");

                return;
            }
            
            if (options.GetFlag("shell"))
            {
                if (techId == 0)
                {
                    if (Modules.RunTrustedInstallerProcess(
                        null,
                        options.GetValue("extra"),
                        options.GetFlag("full")))
                    {
                        Console.WriteLine();
                        Console.WriteLine("[>] Exit.");
                        Console.WriteLine();
                    }
                }
                else if (techId == 1)
                {
                    if (Modules.RunTrustedInstallerProcessWithVirtualLogon(
                        options.GetValue("domain"),
                        options.GetValue("username"),
                        domainRid,
                        null,
                        options.GetValue("extra"),
                        options.GetFlag("full")))
                    {
                        Console.WriteLine();
                        Console.WriteLine("[>] Exit.");
                    }

                    Console.WriteLine("[!] Added virtual domain and user are not removed automatically.");
                    Console.WriteLine("    |-> To remove added virtual user SID   : {0} -m sid -r -d {1} -u {2}",
                        AppDomain.CurrentDomain.FriendlyName,
                        options.GetValue("domain"),
                        options.GetValue("username"));
                    Console.WriteLine("    |-> To remove added virtual domain SID : {0} -m sid -r -d {1}",
                        AppDomain.CurrentDomain.FriendlyName,
                        options.GetValue("domain"));
                    Console.WriteLine();
                }
                else
                {
                    options.GetHelp();
                    Console.WriteLine("Available Technique IDs:\n");
                    Console.WriteLine("\t+ 0 - Leverages SeCreateTokenPrivilege. Uses only --shell flag, --full flag and --command option.");
                    Console.WriteLine("\t+ 1 - Leverages virtual logon. This technique creates virtual domain and account as a side effect.");
                    Console.WriteLine("\n[!] Invalid technique ID.");
                    Console.WriteLine();
                }
            }
            else if (options.GetValue("command") != null)
            {
                if (techId == 0)
                {
                    if (Modules.RunTrustedInstallerProcess(
                        options.GetValue("command"),
                        options.GetValue("extra"),
                        options.GetFlag("full")))
                    {
                        Console.WriteLine();
                        Console.WriteLine("[>] Exit.");
                        Console.WriteLine();
                    }
                }
                else if (techId == 1)
                {
                    if (Modules.RunTrustedInstallerProcessWithVirtualLogon(
                        options.GetValue("domain"),
                        options.GetValue("username"),
                        domainRid,
                        options.GetValue("command"),
                        options.GetValue("extra"),
                        options.GetFlag("full")))
                    {
                        Console.WriteLine();
                        Console.WriteLine("[>] Exit.");
                    }

                    Console.WriteLine("[!] Added virtual domain and user are not removed automatically.");
                    Console.WriteLine("    |-> To remove added virtual user SID   : {0} -m sid -r -d {1} -u {2}",
                        AppDomain.CurrentDomain.FriendlyName,
                        options.GetValue("domain"),
                        options.GetValue("username"));
                    Console.WriteLine("    |-> To remove added virtual domain SID : {0} -m sid -r -d {1}",
                        AppDomain.CurrentDomain.FriendlyName,
                        options.GetValue("domain"));
                    Console.WriteLine();
                }
                else
                {
                    options.GetHelp();
                    Console.WriteLine("Available Technique IDs:\v");
                    Console.WriteLine("\t+ 0 - Leverages SeCreateTokenPrivilege. Uses only --shell flag, --full flag and --command option.");
                    Console.WriteLine("\t+ 1 - Leverages virtual logon. This technique creates virtual domain and account as a side effect.");
                    Console.WriteLine("\n[!] Invalid technique ID.");
                    Console.WriteLine();
                }
            }
            else
            {
                options.GetHelp();
                Console.WriteLine("Available Technique IDs:\n");
                Console.WriteLine("\t+ 0 - Leverages SeCreateTokenPrivilege. Uses only --shell flag, --full flag and --command option.");
                Console.WriteLine("\t+ 1 - Leverages virtual logon. This technique creates virtual domain and account as a side effect.");
                Console.WriteLine();
            }
        }

        public static void SidCommand(CommandLineParser options)
        {
            int domainRid;

            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            try
            {
                domainRid = Convert.ToInt32(options.GetValue("id"));
            }
            catch
            {
                Console.WriteLine("\n[-] Failed to parse RID for virtual domain.\n");

                return;
            }

            if (options.GetFlag("lookup"))
            {
                Modules.LookupSid(
                    options.GetValue("domain"),
                    options.GetValue("username"),
                    options.GetValue("sid"));
            }
            else if (options.GetFlag("remove"))
            {
                if (string.IsNullOrEmpty(options.GetValue("domain")))
                {
                    Console.WriteLine("\n[-] Domain name is not specified.\n");

                    return;
                }

                Modules.RemoveVirtualAccount(options.GetValue("domain"), options.GetValue("username"));
            }
            else if (options.GetFlag("add"))
            {
                if (string.IsNullOrEmpty(options.GetValue("domain")))
                {
                    Console.WriteLine("\n[-] Domain name is not specified.\n");
                    
                    return;
                }

                Modules.AddVirtualAccount(
                    options.GetValue("domain"),
                    options.GetValue("username"),
                    domainRid);
            }
            else
            {
                options.GetHelp();
            }
        }
    }
}
