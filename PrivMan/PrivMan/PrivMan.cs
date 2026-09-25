using PrivMan.Handler;
using PrivMan.Library;
using System;

namespace PrivMan
{
    internal class PrivMan
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("PrivMan - Tool to manipulate token privileges.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "g", "get", "Flag to get token privileges status.");
                options.AddParameter(false, "p", "pid", null, "Specifies a PID to manipulate token privileges.");
                options.AddParameter(false, "d", "disable", null, "Specifies a privilege name string to disable.");
                options.AddParameter(false, "e", "enable", null, "Specifies a privilege name string to enable.");
                options.AddParameter(false, "f", "filter", null, "Specifies a privilege name string to filter.");
                options.AddParameter(false, "r", "remove", null, "Specifies a privilege name string to remove.");
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
