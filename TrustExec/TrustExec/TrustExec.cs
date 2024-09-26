using System;
using System.Collections.Generic;
using TrustExec.Handler;

namespace TrustExec
{
    internal class TrustExec
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();
            var exclusive = new List<string> { "exec", "lookup" };
            string command = Environment.GetEnvironmentVariable("COMSPEC");

            try
            {
                options.SetTitle("TrustExec - Tool to create TrustedInstaller process.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "l", "lookup", "Flag to lookup account name or SID.");
                options.AddFlag(false, "n", "new-console", "Flag to create new console. Use with -x flag.");
                options.AddFlag(false, "x", "exec", "Flag to execute command.");
                options.AddParameter(false, "a", "account", null, "Specifies account name to lookup.");
                options.AddParameter(false, "c", "command", command, "Specifies command to execute. Default is cmd.exe.");
                options.AddParameter(false, "e", "extra", null, "Specifies command to execute. Default is cmd.exe.");
                options.AddParameter(false, "m", "method", "0", "Specifies method ID. Default is 0 (NtCreateToken method).");
                options.AddParameter(false, "s", "sid", null, "Specifies SID to lookup.");
                options.AddExclusive(exclusive);
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
