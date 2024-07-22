using System;
using TokenAssignor.Library;

namespace TokenAssignor.Handler
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
                int nMethodId;
                int nSourcePid;
                string command = options.GetValue("command");

                try
                {
                    nMethodId = Convert.ToInt32(options.GetValue("method"), 10);
                }
                catch
                {
                    Console.WriteLine("[-] Failed to parse method ID.");
                    break;
                }

                try
                {
                    nSourcePid = Convert.ToInt32(options.GetValue("pid"), 10);
                }
                catch
                {
                    Console.WriteLine("[-] Failed to parse PID.");
                    break;
                }

                if (string.IsNullOrEmpty(command))
                {
                    Console.WriteLine("[-] Command to execute is not specified.");
                    break;
                }

                switch (nMethodId)
                {
                    case 0:
                        Modules.GetTokenAssignedProcess(nSourcePid, command);
                        break;
                    case 1:
                        Modules.GetTokenAssignedProcessWithSuspend(nSourcePid, command);
                        break;
                    case 2:
                        Modules.GetTokenAssignedProcessWithSecondaryLogon(nSourcePid, command);
                        break;
                    case 3:
                        Modules.GetTokenAssignedProcessWithParent(nSourcePid, command);
                        break;
                    default:
                        Console.WriteLine("[-] Invalid method ID is specified.");
                        break;
                }
            } while (false);

            Console.WriteLine();
        }
    }
}
