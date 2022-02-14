using System;
using System.Collections.Generic;
using TrustExec.Handler;

namespace TrustExec
{
    class TrustExec
    {
        static void PrintModules()
        {
            Console.WriteLine("Available Modules:\n");
            Console.WriteLine("\t+ exec - Run process as \"NT SERVICE\\TrustedInstaller\".");
            Console.WriteLine("\t+ sid  - Add or remove virtual account's SID.");
            Console.WriteLine();
            Console.WriteLine("[*] To see help for each modules, specify \"-m <Module> -h\" as arguments.\n");
        }


        static void Main(string[] args)
        {
            CommandLineParser options = new CommandLineParser();
            string[] reminder;

            try
            {
                options.SetTitle("TrustExec - Tool to investigate TrustedInstaller capability.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "m", "module", null, "Specifies module name.");
                reminder = options.Parse(args);
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);

                return;
            }
            catch (ArgumentException ex)
            {
                options.GetHelp();
                Console.WriteLine(ex.Message);

                return;
            }

            if (options.GetValue("module") != null)
            {
                StringComparison opt = StringComparison.OrdinalIgnoreCase;
                CommandLineParser subOptions = new CommandLineParser();
                List<string> exclusive;

                if (string.Compare(options.GetValue("module"), "exec", opt) == 0)
                {
                    exclusive = new List<string> { "shell", "command" };

                    try
                    {
                        subOptions.SetTitle("TrustExec - Help for \"exec\" command.");
                        subOptions.SetOptionName("-m exec");
                        subOptions.AddFlag(false, "h", "help", "Displays this help message.");
                        subOptions.AddFlag(false, "s", "shell", "Flag for interactive shell.");
                        subOptions.AddFlag(false, "f", "full", "Flag to enable all available privileges.");
                        subOptions.AddParameter(false, "t", "technique", "0", "Specifies technique ID. Default ID is 0.");
                        subOptions.AddParameter(false, "c", "command", null, "Specifies command to execute.");
                        subOptions.AddParameter(false, "d", "domain", "DefaultDomain", "Specifies domain name to add. Default value is \"DefaultDomain\".");
                        subOptions.AddParameter(false, "u", "username", "DefaultUser", "Specifies username to add. Default value is \"DefaultUser\".");
                        subOptions.AddParameter(false, "i", "id", "110", "Specifies RID for virtual domain. Default value is \"110\".");
                        subOptions.AddExclusive(exclusive);
                        subOptions.Parse(reminder);
                        Execute.ExecCommand(subOptions);
                    }
                    catch (InvalidOperationException ex)
                    {
                        Console.WriteLine(ex.Message);

                        return;
                    }
                    catch (ArgumentException ex)
                    {
                        subOptions.GetHelp();
                        Console.WriteLine("Available Technique IDs:\n");
                        Console.WriteLine("\t+ 0 - Leverages SeCreateTokenPrivilege. Uses only --shell flag, --full flag and --command option.");
                        Console.WriteLine("\t+ 1 - Leverages virtual logon. This technique creates virtual domain and account as a side effect.");
                        Console.WriteLine();

                        Console.WriteLine(ex.Message);

                        return;
                    }
                }
                else if (string.Compare(options.GetValue("module"), "sid", opt) == 0)
                {
                    exclusive = new List<string> { "add", "remove", "lookup" };

                    try
                    {
                        subOptions.SetTitle("TrustExec - Help for \"sid\" command.");
                        subOptions.SetOptionName("-m sid");
                        subOptions.AddFlag(false, "h", "help", "Displays this help message.");
                        subOptions.AddFlag(false, "a", "add", "Flag to add virtual account's SID.");
                        subOptions.AddFlag(false, "r", "remove", "Flag to remove virtual account's SID.");
                        subOptions.AddFlag(false, "l", "lookup", "Flag to lookup SID or account name in local system.");
                        subOptions.AddParameter(false, "d", "domain", null, "Specifies domain name to add or remove. Default value is null.");
                        subOptions.AddParameter(false, "u", "username", null, "Specifies username to add or remove. Default value is null.");
                        subOptions.AddParameter(false, "i", "id", "110", "Specifies RID for virtual domain to add. Default value is \"110\".");
                        subOptions.AddParameter(false, "s", "sid", null, "Specifies SID to lookup.");
                        subOptions.AddExclusive(exclusive);
                        subOptions.Parse(reminder);
                        Execute.SidCommand(subOptions);
                    }
                    catch (InvalidOperationException ex)
                    {
                        Console.WriteLine(ex.Message);

                        return;
                    }
                    catch (ArgumentException ex)
                    {
                        subOptions.GetHelp();
                        Console.WriteLine(ex.Message);

                        return;
                    }
                }
                else
                {
                    Console.WriteLine("\n[-] {0} command is not implemented.\n", options.GetValue("module"));
                }
            }
            else if (options.GetFlag("help"))
            {
                options.GetHelp();
                PrintModules();
            }
            else
            {
                options.GetHelp();
                PrintModules();
            }
        }
    }
}
