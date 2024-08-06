using System;
using ServiceShell.Library;

namespace ServiceShell.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            string command = options.GetValue("command");
            bool bNewConsole = options.GetFlag("new-console");

            if (options.GetFlag("help"))
            {
                options.GetHelp();
                return;
            }

            if (!options.GetFlag("interactive") && !bNewConsole)
            {
                Console.WriteLine("\n[-] -i  or -n option is required.\n");
                return;
            }

            if (string.IsNullOrEmpty(command))
            {
                Console.WriteLine("\n[-] Command is not specified.\n");
                return;
            }

            Console.WriteLine();
            Modules.CreateTrustedInstallerServiceProcess(command, bNewConsole);
            Console.WriteLine();
        }
    }
}
