using System;
using WfpTokenDup.Library;

namespace WfpTokenDup.Handler
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

            var pid = 0;
            var sessionId = 0;
            var handle = IntPtr.Zero;

            try
            {
                if (!string.IsNullOrEmpty(options.GetValue("pid")))
                    pid = Convert.ToInt32(options.GetValue("pid"), 10);
            }
            catch
            {
                Console.WriteLine("\n[-] Failed to parse PID.\n");
                return;
            }

            try
            {
                if (!string.IsNullOrEmpty(options.GetValue("session")))
                    sessionId = Convert.ToInt32(options.GetValue("session"), 10);
            }
            catch
            {
                Console.WriteLine("\n[-] Failed to parse PID.\n");
                return;
            }

            try
            {
                if (!string.IsNullOrEmpty(options.GetValue("value")))
                    handle = new IntPtr(Convert.ToInt32(options.GetValue("value"), 16));
            }
            catch
            {
                Console.WriteLine("\n[-] Failed to parse handle value.\n");
                return;
            }

            Console.WriteLine();

            if (options.GetFlag("system"))
            {
                Modules.GetSystemShell();
            }
            else if ((pid > 0) && (handle != IntPtr.Zero))
            {
                Modules.GetDupicatedTokenAssignedShell(pid, handle);
            }
            else if (pid > 0)
            {
                Console.WriteLine("[-] Missing handle value.");
            }
            else if (sessionId > 0)
            {
                Modules.GetSessionShell(sessionId);
            }
            else if (handle != IntPtr.Zero)
            {
                Console.WriteLine("[-] Missing PID.");
            }
            else
            {
                Console.WriteLine("[-] No options. Try -h flag.");
            }

            Console.WriteLine();
        }
    }
}
