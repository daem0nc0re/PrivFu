using System;
using TokenDump.Library;

namespace TokenDump.Handler
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
                if (options.GetFlag("enum"))
                {
                    if (options.GetFlag("handle"))
                        Modules.GetTokenHandleInformation(options.GetValue("account"));
                    else
                        Modules.GetProcessTokenInformation(options.GetValue("account"));
                }
                else if (options.GetFlag("scan"))
                {
                    int pid;
                    IntPtr hObject;

                    try
                    {
                        pid = Convert.ToInt32(options.GetValue("pid"), 10);
                    }
                    catch
                    {
                        Console.WriteLine("[!] Failed to parse PID.");
                        pid = 0;
                    }

                    if (pid > 0)
                    {
                        if (string.IsNullOrEmpty(options.GetValue("value")))
                        {
                            hObject = IntPtr.Zero;
                        }
                        else
                        {
                            try
                            {
                                hObject = new IntPtr(Convert.ToInt32(options.GetValue("value"), 16));
                            }
                            catch
                            {
                                Console.WriteLine("[!] Failed to parse handle value.");
                                hObject = IntPtr.Zero;
                            }
                        }

                        Modules.GetVerboseTokenInformation(pid, hObject);
                    }
                }
                else
                {
                    Console.WriteLine("[-] No options. Try -h flag.");
                }
            } while (false);

            Console.WriteLine();
        }
    }
}