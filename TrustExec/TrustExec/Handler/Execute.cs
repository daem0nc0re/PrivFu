using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using TrustExec.Library;

namespace TrustExec.Handler
{
    internal class Execute
    {
        public static void ExecCommand(CommandLineParser options)
        {
            int nMethodId;
            var extraGroupSids = new List<string>();

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

            if (!string.IsNullOrEmpty(options.GetValue("extra")))
            {
                var matches = Regex.Matches(
                    options.GetValue("extra"),
                    @"S-1(-\d+){2,}",
                    RegexOptions.IgnoreCase);

                foreach (Match match in matches)
                    extraGroupSids.Add(match.Value.ToUpper());

                if (extraGroupSids.Count == 0)
                    Console.WriteLine("[!] No valid SIDs are specified. Ignored.");
            }

            Console.WriteLine();

            if (options.GetFlag("exec"))
            {
                if (nMethodId == 0)
                {
                    Console.WriteLine("[*] NtCreateToken syscall method is selected.");
                    Modules.RunTrustedInstallerProcess(
                        options.GetValue("command"),
                        options.GetFlag("new-console"),
                        in extraGroupSids);
                }
                else if (nMethodId == 1)
                {
                    Console.WriteLine("[*] Virtual logon method is selected.");
                    Modules.RunTrustedInstallerProcessWithVirtualLogon(
                        options.GetValue("command"),
                        options.GetFlag("new-console"),
                        in extraGroupSids);
                }
                else if (nMethodId == 2)
                {
                    Console.WriteLine("[*] Service logon method is selected.");
                    Modules.RunTrustedInstallerProcessWithServiceLogon(
                        options.GetValue("command"),
                        options.GetFlag("new-console"),
                        in extraGroupSids);
                }
                else if (nMethodId == 3)
                {
                    Console.WriteLine("[*] S4U logon method is selected.");
                    Modules.RunTrustedInstallerProcessWithS4ULogon(
                        options.GetValue("command"),
                        options.GetFlag("new-console"),
                        in extraGroupSids);
                }
                else if (nMethodId == 4)
                {
                    Console.WriteLine("[*] TrustedInstaller service method is selected.");

                    if (extraGroupSids.Count > 0)
                        Console.WriteLine("[!] This method does not support extra group SID option. Specified option will be ignored.");

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
            builder.AppendLine("\t+ 0 - Leverages NtCreateToken syscall.");
            builder.AppendLine("\t+ 1 - Leverages virtual logon.");
            builder.AppendLine("\t+ 2 - Leverages service logon.");
            builder.AppendLine("\t+ 3 - Leverages S4U logon.");
            builder.AppendLine("\t+ 4 - Leverages TrustedInstaller service.");

            return builder.ToString();
        }
    }
}
