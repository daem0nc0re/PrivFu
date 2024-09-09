using System;
using TrustExec.Handler;

namespace TrustExec
{
    internal class TrustExec
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();
            string command = Environment.GetEnvironmentVariable("COMSPEC");

            try
            {
                options.SetTitle("TrustExec - Tool to create TrustedInstaller process.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "n", "new-console", "Flag to create new console.");
                options.AddParameter(true, "m", "method", null, "Specifies method ID.");
                options.AddParameter(false, "c", "command", command, "Specifies command to execute. Default is cmd.exe.");
                options.Parse(args);
                Execute.ExecCommand(options);
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
