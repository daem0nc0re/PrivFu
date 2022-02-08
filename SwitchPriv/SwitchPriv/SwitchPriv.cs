using System;
using System.Collections.Generic;
using SwitchPriv.Handler;

using System.Security.Principal;
using SwitchPriv.Library;

namespace SwitchPriv
{
    class SwitchPriv
    {
        static void Main(string[] args)
        {
            CommandLineParser options = new CommandLineParser();
            var exclusive = new List<string> { "enable", "disable", "remove", "get", "integrity" };

            try
            {
                options.SetTitle("SwitchPriv - Tool to control token privileges.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "e", "enable", null, "Specifies token privilege to enable. Case insensitive.");
                options.AddParameter(false, "d", "disable", null, "Specifies token privilege to disable. Case insensitive.");
                options.AddParameter(false, "r", "remove", null, "Specifies token privilege to remove. Case insensitive.");
                options.AddParameter(false, "p", "pid", null, "Specifies the target PID. Default specifies PPID.");
                options.AddParameter(false, "i", "integrity", null, "Specifies integrity level to set.");
                options.AddFlag(false, "g", "get", "Flag to get available privileges for the target process.");
                options.AddFlag(false, "s", "system", "Flag to run as \"NT AUTHORITY\\SYSTEM\".");
                options.AddFlag(false, "l", "list", "Flag to list values for --enable, --disable, --remove and --integrity options.");
                options.AddExclusive(exclusive);
                options.Parse(args);
                Execute.Run(options);
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);

                return;
            }
            catch (ArgumentException ex)
            {
                options.GetHelp();
                Console.WriteLine(ex.Message);

                return;
            }
        }
    }
}
