using System;
using System.Collections.Generic;
using S4uDelegator.Handler;

namespace S4uDelegator
{
    internal class S4uDelegator
    {
        static void Main(string[] args)
        {
            var exclusive = new List<string> { "lookup", "execute" };
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("S4uDelegator - Tool for S4U Logon.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "l", "lookup", "Flag to lookup account SID.");
                options.AddFlag(false, "x", "execute", "Flag to execute command.");
                options.AddParameter(false, "c", "command", "cmd.exe", "Specifies command to execute. Default is cmd.exe.");
                options.AddParameter(false, "d", "domain", null, "Specifies domain name to lookup or S4U logon.");
                options.AddParameter(false, "e", "extra", null, "Specifies group SIDs you want to add for S4U logon with comma separation.");
                options.AddParameter(false, "n", "name", null, "Specifies account name to lookup or S4U logon.");
                options.AddParameter(false, "s", "sid", null, "Specifies SID to lookup.");
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
