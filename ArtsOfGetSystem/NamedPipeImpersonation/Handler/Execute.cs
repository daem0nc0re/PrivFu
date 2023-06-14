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

            Modules.GetSystemWithNamedPipe();

            Console.WriteLine();
        }
    }
}
