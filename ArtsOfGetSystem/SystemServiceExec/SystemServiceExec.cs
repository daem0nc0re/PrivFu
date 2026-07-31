using System;
using SystemServiceExec.Handler;

namespace SystemServiceExec
{
    internal class SystemServiceExec
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("SystemServiceExec - PoC to get SYSTEM privileges with service creation method.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "c", "command", "cmd.exe", "Specifies a command to execute. Default \"cmd.exe\".");
                options.AddParameter(false, "u", "username", null, "Specifies a username of Administrators group member (Optional).");
                options.AddParameter(false, "d", "domain", null, "Specifies a domain name for Administrators group member (Optional).");
                options.AddParameter(false, "p", "password", null, "Specifies a password for Administrators group member (Optional).");
                options.AddParameter(false, "w", "wait", "300", "Specifies a wait time for service in milliseconds (Default: 300).");
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
