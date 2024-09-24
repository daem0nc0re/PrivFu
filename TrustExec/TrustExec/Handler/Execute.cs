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
                Console.WriteLine("Available Method IDs:\v");
                Console.WriteLine("\t+ 0 - Leverages SeCreateTokenPrivilege.");
                Console.WriteLine("\t+ 1 - Leverages virtual logon.");
                Console.WriteLine("\t+ 2 - Leverages service logon.");
                Console.WriteLine("\t+ 3 - Leverages S4U logon.");
                Console.WriteLine("\t+ 4 - Leverages TrustedInstaller service.\n");

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

            if (options.GetFlag("exec"))
            {
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
                else if (nMethodId == 2)
                {
                    if (Modules.RunTrustedInstallerProcessWithServiceLogon(options.GetValue("command"), options.GetFlag("new-console")))
                        Console.WriteLine("[>] Exit.");
                }
                else if (nMethodId == 3)
                {
                    if (Modules.RunTrustedInstallerProcessWithS4ULogon(options.GetValue("command"), options.GetFlag("new-console")))
                        Console.WriteLine("[>] Exit.");
                }
                else if (nMethodId == 4)
                {
                    if (Modules.RunTrustedInstallerProcessWithService(options.GetValue("command"), options.GetFlag("new-console")))
                        Console.WriteLine("[>] Exit.");
                }
                else
                {
                    options.GetHelp();
                    Console.WriteLine("Available Method IDs:\v");
                    Console.WriteLine("\t+ 0 - Leverages SeCreateTokenPrivilege.");
                    Console.WriteLine("\t+ 1 - Leverages virtual logon.");
                    Console.WriteLine("\t+ 2 - Leverages service logon.");
                    Console.WriteLine("\t+ 3 - Leverages S4U logon.");
                    Console.WriteLine("\t+ 4 - Leverages TrustedInstaller service.");
                    Console.WriteLine("\n[!] Invalid technique ID.");
                }
            }
            else if (options.GetFlag("lookup"))
            {
                Modules.LookupAccountSid(options.GetValue("account"), options.GetValue("sid"));
            }
            else
            {
                Console.WriteLine("[-] No valid options. Try -h option.");
            }

            Console.WriteLine();
        }
    }
}
