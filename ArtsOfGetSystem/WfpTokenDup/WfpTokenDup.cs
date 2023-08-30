using System;
using WfpTokenDup.Handler;

namespace WfpTokenDup
{
    internal class WfpTokenDup
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("WfpTokenDup - PoC for token stealing with Windows Filtering Platform.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "S", "system", "Flag to get SYSTEM shell.");
                options.AddParameter(false, "p", "pid", null, "Specifies PID to duplicate token handle in decimal format.");
                options.AddParameter(false, "v", "value", null, "Specifies handle value to duplicate token handle in hex format.");
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
