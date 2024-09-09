using System;
using TrustExec.Library;

namespace TrustExec.Handler
{
    internal class Execute
    {
        public static void ExecCommand(CommandLineParser options)
        {
            int nMethodId;

            if (options.GetFlag("help"))
            {
                options.GetHelp();
                Console.WriteLine("Available Method IDs:\n");
                Console.WriteLine("\t+ 0 - Leverages SeCreateTokenPrivilege. Uses only --shell flag and --command option.");
                Console.WriteLine("\t+ 1 - Leverages virtual logon. This technique creates virtual domain and account as a side effect.");

                return;
            }

            try
            {
                nMethodId = Convert.ToInt32(options.GetValue("method"));
            }
            catch
            {
                Console.WriteLine("\n[-] Failed to parse technique ID.\n");
                return;
            }

            Console.WriteLine();

            if (nMethodId == 0)
            {
                if (Modules.RunTrustedInstallerProcess(options.GetValue("command"), options.GetFlag("new-console")))
                    Console.WriteLine("[>] Exit.");
            }
            else if (nMethodId == 1)
            {
                if (Modules.RunTrustedInstallerProcessWithVirtualLogon(options.GetValue("command"), options.GetFlag("new-console")))
                    Console.WriteLine("[>] Exit.");
            }
            else
            {
                options.GetHelp();
                Console.WriteLine("Available Method IDs:\v");
                Console.WriteLine("\t+ 0 - Leverages SeCreateTokenPrivilege. Uses only --shell flag, --full flag and --command option.");
                Console.WriteLine("\t+ 1 - Leverages virtual logon. This technique creates virtual domain and account as a side effect.");
                Console.WriteLine("\n[!] Invalid technique ID.");
            }

            Console.WriteLine();
        }
    }
}
