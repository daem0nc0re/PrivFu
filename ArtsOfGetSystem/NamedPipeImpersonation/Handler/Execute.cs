using System;
using NamedPipeImpersonation.Library;

namespace NamedPipeImpersonation.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();
                return;
            }

            Console.WriteLine();

            try
            {
                Globals.timeout = Convert.ToInt32(options.GetValue("timeout"));
            }
            catch
            {
                Console.WriteLine("[-] Failed to parse timeout. Use default value (3,000 ms).");
                Globals.timeout = 3000;
            }

            Modules.GetSystemWithNamedPipe();

            Console.WriteLine();
        }
    }
}
