using System;
using TokenStealing.Library;

namespace TokenStealing.Handler
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

            if (options.GetFlag("secondary"))
                Modules.GetSystemBySecondaryLogon();
            else
                Modules.GetSystemByTokenImpersonation();

            Console.WriteLine();
        }
    }
}
