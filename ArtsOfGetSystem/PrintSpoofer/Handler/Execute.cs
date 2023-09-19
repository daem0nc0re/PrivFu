using System;
using PrintSpoofer.Library;

namespace PrintSpoofer.Handler
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

            int sessionId = 0;

            Console.WriteLine();

            do
            {
                if (!string.IsNullOrEmpty(options.GetValue("session")))
                {
                    try
                    {
                        sessionId = Convert.ToInt32(options.GetValue("session"), 10);

                        if (sessionId < 0)
                        {
                            Console.WriteLine("[!] Session ID must be positive integer.");
                            break;
                        }
                    }
                    catch
                    {
                        Console.WriteLine("[!] Failed to parse session ID.");
                        break;
                    }
                }

                if (!string.IsNullOrEmpty(options.GetValue("timeout")))
                {
                    try
                    {
                        Globals.Timeout = Convert.ToInt32(options.GetValue("timeout"), 10);

                        if (Globals.Timeout < 0)
                        {
                            Console.WriteLine("[!] Timeout duration must be positive integer.");
                            break;
                        }
                    }
                    catch
                    {
                        Console.WriteLine("[!] Failed to parse timeout duration.");
                        break;
                    }
                }

                Modules.GetSystem(
                    options.GetValue("command"),
                    sessionId,
                    options.GetFlag("interactive"));
            } while (false);

            Console.WriteLine();
        }
    }
}
