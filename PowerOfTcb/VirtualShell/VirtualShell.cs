using System;
using System.Collections.Generic;
using VirtualShell.Handler;

namespace VirtualShell
{
    internal class VirtualShell
    {
        static void Main(string[] args)
        {
            CommandLineParser options = new CommandLineParser();
            var exclusive = new List<string> { "interactive", "new-console" };
            string command = Environment.GetEnvironmentVariable("COMSPEC");

            try
            {
                options.SetTitle("VirtualShell - PoC to create virtual account process.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "c", "command", command, "Specifies command to execute. Default is cmd.exe.");
                options.AddFlag(false, "i", "interactive", "Flag to execute process with same console.");
                options.AddFlag(false, "n", "new-console", "Flag to execute process with new console.");
                options.AddExclusive(exclusive);
                options.Parse(args);
                Execute.Run(options);
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);
            }
            catch (ArgumentException ex)
            {
                options.GetHelp();
                Console.WriteLine(ex.Message);
            }
        }
    }
}
