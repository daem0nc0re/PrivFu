using System;
using SystemTaskExec.Library;

namespace SystemTaskExec.Handler
{
    internal class Execute
    {
        internal static void Run(CommandLineParser options)
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
                var binpath = string.Format("{0}{1}",
                    AppDomain.CurrentDomain.BaseDirectory,
                    AppDomain.CurrentDomain.FriendlyName);
                var arguments = string.Format("-c \"{0}\"", options.GetValue("command"));

                Modules.GetSystemTaskProcess(
                    options.GetValue("username"),
                    options.GetValue("domain"),
                    options.GetValue("password"),
                    Globals.TaskName,
                    binpath,
                    arguments);
            }

            Console.WriteLine();
        }
    }
}
