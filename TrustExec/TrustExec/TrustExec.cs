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
            Console.WriteLine("    + exec - Run process as \"NT SERVICE\\TrustedInstaller\".");
            Console.WriteLine("    + sid  - Add or remove virtual account's SID.");
            Console.WriteLine();
            Console.WriteLine("[*] To see help for each modules, specify \"-m <Module> -h\" as arguments.\n");
        }


        static string[] RemoveFromArguments(string[] inputArgs, string[] argsToRemove)
        {
            List<string> commandLine = new List<string>();
            bool found;

            for (var idx = 0; idx < inputArgs.Length; idx++)
            {
                found = false;

                for (var innerIdx = 0; innerIdx < argsToRemove.Length; innerIdx++)
                {
                    if (inputArgs[idx] == argsToRemove[innerIdx])
                    {
                        found = true;
                        break;
                    }
                }

                if (found)
                    idx++;
                else
                    commandLine.Add(inputArgs[idx]);
            }

            return commandLine.ToArray();
        }


        static void Main(string[] args)
        {
            CommandLineParser options = new CommandLineParser();
            options.SetTitle("TrustExec - Tool to investigate TrustedInstaller capability.");
            options.Add(false, "h", "help", false, "Displays this help message.");
            options.Add(false, "m", "module", null, "Specifies module name.");
            options.Parse(args);

            if (options.GetValue("module") != null)
            {
                StringComparison opt = StringComparison.OrdinalIgnoreCase;
                string[] argsToRemove = new string[] { "-m", "-module" };
                string[] commandLine = RemoveFromArguments(args, argsToRemove);
                CommandLineParser strippedOptions = new CommandLineParser();

                if (string.Compare(options.GetValue("module"), "exec", opt) == 0)
                {
                    strippedOptions.SetTitle("TrustExec - Help for \"exec\" command.");
                    strippedOptions.SetOptionName("-m exec");
                    strippedOptions.Add(false, "h", "help", false, "Displays this help message.");
                    strippedOptions.Add(false, "s", "shell", false, "Flag for interactive shell.");
                    strippedOptions.Add(false, "c", "command", null, "Specifies command to execute.");
                    strippedOptions.Add(false, "d", "domain", "DefaultDomain", "Specifies domain name to add. Default value is \"DefaultDomain\".");
                    strippedOptions.Add(false, "u", "username", "DefaultUser", "Specifies username to add. Default value is \"DefaultUser\".");
                    strippedOptions.Add(false, "i", "id", "110", "Specifies RID for virtual domain. Default value is \"110\".");
                    strippedOptions.Add(false, "f", "full", false, "Flag to enable all available privileges.");
                    strippedOptions.Parse(commandLine);
                    Execute.ExecCommand(strippedOptions);
                }
                else if (string.Compare(options.GetValue("module"), "sid", opt) == 0)
                {
                    strippedOptions.SetTitle("TrustExec - Help for \"sid\" command.");
                    strippedOptions.SetOptionName("-m sid");
                    strippedOptions.Add(false, "h", "help", false, "Displays this help message.");
                    strippedOptions.Add(false, "a", "add", false, "Flag to add virtual account's SID.");
                    strippedOptions.Add(false, "r", "remove", false, "Flag to remove virtual account's SID.");
                    strippedOptions.Add(false, "d", "domain", null, "Specifies domain name to add or remove. Default value is null.");
                    strippedOptions.Add(false, "u", "username", null, "Specifies username to add or remove. Default value is null.");
                    strippedOptions.Add(false, "i", "id", "110", "Specifies RID for virtual domain to add. Default value is \"110\".");
                    strippedOptions.Add(false, "s", "sid", null, "Specifies SID to lookup.");
                    strippedOptions.Add(false, "l", "lookup", false, "Flag to lookup SID or account name in local system.");
                    strippedOptions.Parse(commandLine);
                    Execute.SidCommand(strippedOptions);
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
