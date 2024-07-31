using System;
using System.Collections.Generic;
using TokenDump.Handler;

namespace TokenDump
{
    internal class TokenDump
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();
            var exclusive = new List<string> { "enum", "scan" };

            try
            {
                options.SetTitle("TokenDump - Tool to dump processs token information.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "d", "debug", "Flag to enable SeDebugPrivilege.");
                options.AddFlag(false, "e", "enum", "Flag to enumerate brief information tokens for processes or handles.");
                options.AddFlag(false, "T", "thread", "Flag to scan thead tokens. Use with -e option.");
                options.AddFlag(false, "H", "handle", "Flag to scan token handles. Use with -e option.");
                options.AddFlag(false, "s", "scan", "Flag to get verbose information for a specific process, thread or handle.");
                options.AddParameter(false, "a", "account", null, "Specifies account name filter string. Use with -e flag.");
                options.AddParameter(false, "p", "pid", null, "Specifies a target PID in decimal format. Use with -s flag, or -e and -H flag.");
                options.AddParameter(false, "t", "tid", null, "Specifies a target TID in decimal format. Use with -s flag and -p option.");
                options.AddParameter(false, "v", "value", null, "Specifies a token handle value in hex format. Use with -s flag and -p option.");
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
