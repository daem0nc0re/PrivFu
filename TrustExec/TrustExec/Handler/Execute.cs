using System;
using TrustExec.Library;

namespace TrustExec.Handler
{
    class Execute
    {
        public static void ExecCommand(CommandLineParser options)
        {
            int groupId;

            if (options.GetFlag("help"))
            {
                options.GetHelp();
                return;
            }

            try
            {
                groupId = Convert.ToInt32(options.GetValue("id"));
            }
            catch
            {
                Console.WriteLine("\n[-] Failed to parse RID for virtual group.\n");
                return;
            }
            
            if (options.GetFlag("shell"))
            {
                if (Modules.RunTrustedInstallerProcess(
                    options.GetValue("domain"),
                    options.GetValue("username"),
                    groupId,
                    null,
                    options.GetFlag("full")))
                {
                    Console.WriteLine();
                    Console.WriteLine("[>] Exit.");
                }

                Console.WriteLine("[!] Added virtual domain and account are not removed automatically.");
                Console.WriteLine("    |-> To remove added virtual account SID : {0} -m sid -r -d {1} -u {2}",
                    AppDomain.CurrentDomain.FriendlyName,
                    options.GetValue("domain"),
                    options.GetValue("username"));
                Console.WriteLine("    |-> To remove added virtual domain SID  : {0} -m sid -r -d {1}",
                    AppDomain.CurrentDomain.FriendlyName,
                    options.GetValue("domain"));
                Console.WriteLine();
            }
            else if (options.GetValue("command") != null)
            {
                if (Modules.RunTrustedInstallerProcess(
                    options.GetValue("domain"),
                    options.GetValue("username"),
                    groupId,
                    options.GetValue("command"),
                    options.GetFlag("full")))
                {
                    Console.WriteLine();
                    Console.WriteLine("[>] Exit.");
                }

                Console.WriteLine("[!] Added virtual domain and account are not removed automatically.");
                Console.WriteLine("    |-> To remove added virtual account SID : {0} -m sid -r -d {1} -u {2}",
                    AppDomain.CurrentDomain.FriendlyName,
                    options.GetValue("domain"),
                    options.GetValue("username"));
                Console.WriteLine("    |-> To remove added virtual domain SID  : {0} -m sid -r -d {1}",
                    AppDomain.CurrentDomain.FriendlyName,
                    options.GetValue("domain"));
                Console.WriteLine();
            }
            else
            {
                options.GetHelp();
            }
        }

        public static void SidCommand(CommandLineParser options)
        {
            int groupId;

            if (options.GetFlag("help"))
            {
                options.GetHelp();
                return;
            }

            try
            {
                groupId = Convert.ToInt32(options.GetValue("id"));
            }
            catch
            {
                Console.WriteLine("\n[-] Failed to parse RID for virtual group.\n");
                return;
            }

            if (options.GetFlag("lookup"))
            {
                Modules.SidLookup(
                    options.GetValue("domain"),
                    options.GetValue("username"),
                    options.GetValue("sid"));
            }
            else if (options.GetFlag("remove"))
            {
                if (options.GetValue("domain") == null)
                {
                    Console.WriteLine("\n[-] Domain name is not specified.\n");
                    return;
                }

                Modules.RemoveVirtualAccount(options.GetValue("domain"), options.GetValue("username"));
            }
            else if (options.GetFlag("add"))
            {
                if (options.GetValue("domain") == null)
                {
                    Console.WriteLine("\n[-] Domain name is not specified.\n");
                    return;
                }

                Modules.AddVirtualAccount(options.GetValue("domain"), options.GetValue("username"), groupId);
            }
            else
            {
                options.GetHelp();
            }
        }
    }
}
