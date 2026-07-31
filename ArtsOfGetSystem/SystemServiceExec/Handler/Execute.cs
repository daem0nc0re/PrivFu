using System;
using SystemServiceExec.Library;

namespace SystemServiceExec.Handler
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

            if (Helpers.IsSystemToken(new IntPtr(-6)))
            {
                Modules.CreateDesktopProcess(options.GetValue("command"));
            }
            else
            {
                int nDelayMilliseconds;
                var executable = string.Format("{0}{1}",
                    AppDomain.CurrentDomain.BaseDirectory,
                    AppDomain.CurrentDomain.FriendlyName);
                var binpath = string.Format("{0} -c \"{1}\"",
                    executable,
                    options.GetValue("command"));

                try
                {
                    nDelayMilliseconds = Convert.ToInt32(options.GetValue("wait"));
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[!] Failed to parse -w parameter: {0}\n", ex.Message);
                    return;
                }

                Modules.GetSystemServiceProcess(
                    options.GetValue("username"),
                    options.GetValue("domain"),
                    options.GetValue("password"),
                    Globals.ServiceName,
                    binpath,
                    nDelayMilliseconds);
            }

            Console.WriteLine();
        }
    }
}
