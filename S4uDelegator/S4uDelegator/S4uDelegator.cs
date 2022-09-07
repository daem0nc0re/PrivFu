using System;
using S4uDelegator.Handler;

namespace S4uDelegator
{
    internal class S4uDelegator
    {
        static void PrintModules()
        {
            Console.WriteLine("Available Modules:\n");
            Console.WriteLine("\t+ lookup - Lookup account's SID.");
            Console.WriteLine("\t+ shell  - Perform S4U logon and get shell.");
            Console.WriteLine();
            Console.WriteLine("[*] To see help for each modules, specify \"-m <Module> -h\" as arguments.\n");
        }


        static void Main(string[] args)
        {
            StringComparison opt = StringComparison.OrdinalIgnoreCase;
            CommandLineParser subOptions = new CommandLineParser();
            CommandLineParser options = new CommandLineParser();
            string[] reminder;

            try
            {
                options.SetTitle("S4uDelegator - Tool for S4U Logon.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(true, "m", "module", null, "Specifies module name.");
                reminder = options.Parse(args);

                if (string.Compare(options.GetValue("module"), "lookup", opt) == 0)
                {
                    subOptions.SetTitle("S4Util - Help for \"lookup\" command.");
                    subOptions.SetOptionName("-m lookup");
                    subOptions.AddFlag(false, "h", "help", "Displays this help message.");
                    subOptions.AddParameter(false, "d", "domain", null, "Specifies domain name to lookup.");
                    subOptions.AddParameter(false, "u", "username", null, "Specifies username to lookup.");
                    subOptions.AddParameter(false, "s", "sid", null, "Specifies SID to lookup.");
                    subOptions.Parse(reminder);
                    Execute.LookupCommand(subOptions);
                }
                else if (string.Compare(options.GetValue("module"), "shell", opt) == 0)
                {
                    subOptions.SetTitle("S4Util - Help for \"shell\" command.");
                    subOptions.SetOptionName("-m shell");
                    subOptions.AddFlag(false, "h", "help", "Displays this help message.");
                    subOptions.AddParameter(false, "d", "domain", null, "Specifies domain name for S4U logon.");
                    subOptions.AddParameter(false, "u", "username", null, "Specifies local username for S4U logon.");
                    subOptions.AddParameter(false, "s", "sid", null, "Specifies local account's SID.");
                    subOptions.AddParameter(false, "e", "extra", null, "Specifies group SIDs you want to add with comma separation.");
                    subOptions.Parse(reminder);
                    Execute.ShellCommand(subOptions);
                }
                else
                {
                    Console.WriteLine("\n[-] {0} command is not implemented.\n", options.GetValue("module"));
                }
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);

                return;
            }
            catch (ArgumentException ex)
            {
                options.GetHelp();
                PrintModules();
                Console.WriteLine(ex.Message);

                return;
            }
        }
    }
}
