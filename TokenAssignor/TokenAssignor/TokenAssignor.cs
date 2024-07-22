using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using TokenAssignor.Handler;
using TokenAssignor.Library;

namespace TokenAssignor
{
    internal class TokenAssignor
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess)
            {
                Console.WriteLine("\n[!] In 64 bit OS, must be built as a 64 bit process binary.\n");
                return;
            }

            try
            {
                options.SetTitle("TokenAssignor - Tool to execute token assigned process.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "c", "command", Environment.GetEnvironmentVariable("COMSPEC"), "Specifies a command to execute. Default is cmd.exe.");
                options.AddParameter(true, "m", "method", null, "Specifies a method ID (0 - 3).");
                options.AddParameter(true, "p", "pid", null, "Specifies a source PID for token stealing.");
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
