using System;
using System.Text;
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
                Console.WriteLine(GetExtraHelpMessage());
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
                    Modules.RunTrustedInstallerProcess(options.GetValue("command"), options.GetFlag("new-console"));
                }
                else if (nMethodId == 1)
                {
                    Modules.RunTrustedInstallerProcessWithVirtualLogon(options.GetValue("command"), options.GetFlag("new-console"));
                }
                else if (nMethodId == 2)
                {
                    Modules.RunTrustedInstallerProcessWithServiceLogon(options.GetValue("command"), options.GetFlag("new-console"));
                }
                else if (nMethodId == 3)
                {
                    Modules.RunTrustedInstallerProcessWithS4ULogon(options.GetValue("command"), options.GetFlag("new-console"));
                }
                else if (nMethodId == 4)
                {
                    Modules.RunTrustedInstallerProcessWithService(options.GetValue("command"), options.GetFlag("new-console"));
                }
                else
                {
                    options.GetHelp();
                    Console.WriteLine(GetExtraHelpMessage());
                    Console.WriteLine("[!] Invalid technique ID.");
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


        private static string GetExtraHelpMessage()
        {
            var builder = new StringBuilder();
            builder.AppendLine("Available Method IDs:\v");
            builder.AppendLine("\t+ 0 - Leverages SeCreateTokenPrivilege.");
            builder.AppendLine("\t+ 1 - Leverages virtual logon.");
            builder.AppendLine("\t+ 2 - Leverages service logon.");
            builder.AppendLine("\t+ 3 - Leverages S4U logon.");
            builder.AppendLine("\t+ 4 - Leverages TrustedInstaller service.");

            return builder.ToString();
        }
    }
}
