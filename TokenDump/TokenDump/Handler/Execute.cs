using System;
using TokenDump.Library;

namespace TokenDump.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            string account = options.GetValue("account");
            bool debug = options.GetFlag("debug");

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
                        Modules.GetTokenHandleInformation(account, debug);
                    else if (options.GetFlag("thread"))
                        Modules.GetThreadTokenInformation(account, debug);
                    else
                        Modules.GetProcessTokenInformation(account, debug);
                }
                else if (options.GetFlag("scan"))
                {
                    int pid;
                    int tid;
                    IntPtr hObject;

                    try
                    {
                        pid = Convert.ToInt32(options.GetValue("pid"), 10);
                    }
                    catch
                    {
                        Console.WriteLine("[!] Failed to parse PID.");
                        break;
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
                                break;
                            }
                        }

                        if (string.IsNullOrEmpty(options.GetValue("tid")))
                        {
                            tid = 0;
                        }
                        else
                        {
                            try
                            {
                                tid = Convert.ToInt32(options.GetValue("tid"), 10);
                            }
                            catch
                            {
                                Console.WriteLine("[!] Failed to parse TID value.");
                                break;
                            }
                        }

                        Modules.GetVerboseTokenInformation(pid, tid, hObject, debug);
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