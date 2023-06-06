using System;
using TokenStealing.Handler;

namespace TokenStealing
{
    internal class TokenStealing
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("TokenStealing - PoC to get SYSTEM privileges with token stealing method.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "f", "full", "Flag to enable all token privileges.");
                options.AddFlag(false, "s", "secondary", "Flag to use Secondary Logon Service.");
                options.Parse(args);

                Execute.Run(options);
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);
            }
            catch (ArgumentException ex)
            {
                options.GetHelp();
                Console.WriteLine(ex.Message);
            }
        }
    }
}
