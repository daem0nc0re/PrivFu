using System;
using System.Collections.Generic;
using UserRightsUtil.Handler;

namespace UserRightsUtil
{
    internal class UserRightsUtil
    {
        static void PrintModules()
        {
            Console.WriteLine("Available Modules:\n");
            Console.WriteLine("\t+ enum   - Enumerate user rights for specific account.");
            Console.WriteLine("\t+ find   - Find accounts have a specific user right.");
            Console.WriteLine("\t+ lookup - Lookup account's SID.");
            Console.WriteLine("\t+ manage - Grant or revoke user rights.");
            Console.WriteLine();
            Console.WriteLine("[*] To see help for each modules, specify \"-m <Module> -h\" as arguments.\n");
        }


        static void Main(string[] args)
        {
            StringComparison opt = StringComparison.OrdinalIgnoreCase;
            CommandLineParser subOptions = new CommandLineParser();
            List<string> exclusive;
            CommandLineParser options = new CommandLineParser();
            string[] reminder;

            try
            {
                options.SetTitle("UserRightsUtil - User rights management utility.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(true, "m", "module", null, "Specifies module name.");
                reminder = options.Parse(args);

                if (string.Compare(options.GetValue("module"), "enum", opt) == 0)
                {
                    subOptions.SetTitle("S4Util - Help for \"enum\" command.");
                    subOptions.SetOptionName("-m enum");
                    subOptions.AddFlag(false, "h", "help", "Displays this help message.");
                    subOptions.AddParameter(false, "d", "domain", null, "Specifies domain name to lookup.");
                    subOptions.AddParameter(false, "u", "username", null, "Specifies username to lookup.");
                    subOptions.AddParameter(false, "s", "sid", null, "Specifies SID to lookup.");
                    subOptions.Parse(reminder);
                    Execute.EnumCommand(subOptions);
                }
                else if (string.Compare(options.GetValue("module"), "find", opt) == 0)
                {
                    subOptions.SetTitle("S4Util - Help for \"find\" command.");
                    subOptions.SetOptionName("-m find");
                    subOptions.AddFlag(false, "h", "help", "Displays this help message.");
                    subOptions.AddFlag(false, "l", "list", "Displays user rights list for --right option.");
                    subOptions.AddParameter(false, "r", "right", null, "Specifies user right to find.");
                    subOptions.Parse(reminder);
                    Execute.FindCommand(subOptions);
                }
                else if (string.Compare(options.GetValue("module"), "lookup", opt) == 0)
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
                else if (string.Compare(options.GetValue("module"), "manage", opt) == 0)
                {
                    exclusive = new List<string> { "grant", "revoke" };

                    subOptions.SetTitle("S4Util - Help for \"manage\" command.");
                    subOptions.SetOptionName("-m manage");
                    subOptions.AddFlag(false, "h", "help", "Displays this help message.");
                    subOptions.AddFlag(false, "l", "list", "Displays user rights list for --grant and --revoke options.");
                    subOptions.AddParameter(false, "g", "grant", null, "Specifies a user right to grant.");
                    subOptions.AddParameter(false, "r", "revoke", null, "Specifies a user right to revoke.");
                    subOptions.AddParameter(false, "d", "domain", null, "Specifies domain name to lookup.");
                    subOptions.AddParameter(false, "u", "username", null, "Specifies username to lookup.");
                    subOptions.AddParameter(false, "s", "sid", null, "Specifies SID to lookup.");
                    subOptions.AddExclusive(exclusive);
                    subOptions.Parse(reminder);
                    Execute.ManageCommand(subOptions);
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
