using System;
using SystemServiceExec.Handler;
using SystemServiceExec.Library;

namespace SystemServiceExec
{
    internal class SystemServiceExec
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();
            Console.CancelKeyPress += new ConsoleCancelEventHandler(CancelHandler);

            try
            {
                options.SetTitle("SystemServiceExec - PoC to get SYSTEM privileges with service creation method.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "c", "command", "cmd.exe", "Specifies a command to execute. Default \"cmd.exe\".");
                options.AddParameter(false, "u", "username", null, "Specifies a username of Administrators group member (Optional).");
                options.AddParameter(false, "d", "domain", null, "Specifies a domain name for Administrators group member (Optional).");
                options.AddParameter(false, "p", "password", null, "Specifies a password for Administrators group member (Optional).");
                options.AddParameter(false, "w", "wait", "100", "Specifies a wait time for service in milliseconds (Default: 100).");
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


        private static void CancelHandler(object sender, ConsoleCancelEventArgs args)
        {
            Console.WriteLine("[*] Pressed Ctrl+C, aborting...");

            if (Globals.IsServiceCreated && !Globals.IsServiceDeleted)
                Console.WriteLine("[!] Failed to delete \"{0}\" service.", Globals.ServiceName);

            Console.WriteLine();
        }
    }
}
