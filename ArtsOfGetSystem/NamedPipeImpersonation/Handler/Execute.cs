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

            do
            {
                try
                {
                    Globals.Timeout = Convert.ToInt32(options.GetValue("timeout"));
                }
                catch
                {
                    Console.WriteLine("[-] Failed to parse timeout. Use default value (3,000 ms).");
                    Globals.Timeout = 3000;
                }

                try
                {
                    int methodId = Convert.ToInt32(options.GetValue("method"));

                    if (methodId == 0)
                        Globals.UseDropper = false;
                    else if (methodId == 1)
                        Globals.UseDropper = true;
                    else
                        break;
                }
                catch
                {
                    Console.WriteLine("[-] Failed to specify method.");
                    break;
                }

                Modules.GetSystemWithNamedPipe();
            } while (false);

            Console.WriteLine();
        }
    }
}
