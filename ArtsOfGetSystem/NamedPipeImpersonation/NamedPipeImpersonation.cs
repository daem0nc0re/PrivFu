using System;
using NamedPipeImpersonation.Handler;

namespace NamedPipeImpersonation
{
    internal class NamedPipeImpersonation
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("NamedPipeImpersonation - PoC to get SYSTEM privileges with named pipe method.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
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
