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
                options.AddParameter(true, "m", "method", null, "Specifies method. '0' for in-memory, '1' for dropper.");
                options.AddParameter(false, "t", "timeout", "3000", "Specifies timeout in milliseconds. Default is 3,000 ms.");
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
