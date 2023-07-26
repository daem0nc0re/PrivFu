using System;
using TokenDump.Handler;

namespace TokenDump
{
    internal class TokenDump
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("TokenDump - Tool to dump processs token information.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "e", "enum", "Flag to enumerate brief information tokens for processes or handles.");
                options.AddFlag(false, "t", "thread", "Flag to scan thead tokens. Use with -e option.");
                options.AddFlag(false, "H", "handle", "Flag to scan token handles. Use with -e option.");
                options.AddFlag(false, "s", "scan", "Flag to get verbose information for a specific process or handle.");
                options.AddParameter(false, "a", "account", null, "Specifies account name filter string. Use with -e flag.");
                options.AddParameter(false, "p", "pid", null, "Specifies a targer PID in decimal format. Use with -s flag.");
                options.AddParameter(false, "v", "value", null, "Specifies a token handle value in hex format. Use with -s flag.");
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
