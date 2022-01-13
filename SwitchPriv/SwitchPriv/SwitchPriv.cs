using SwitchPriv.Handler;

namespace SwitchPriv
{
    class SwitchPriv
    {
        static void Main(string[] args)
        {
            CommandLineParser options = new CommandLineParser();
            options.SetTitle("SwitchPriv - Tool to control token privileges.");
            options.Add(false, "h", "help", false, "Displays this help message.");
            options.Add(false, "e", "enable", string.Empty, "Specifies token privilege to enable. Case insensitive.");
            options.Add(false, "d", "disable", string.Empty, "Specifies token privilege to disable. Case insensitive.");
            options.Add(false, "p", "pid", string.Empty, "Specifies the target PID. Default specifies PPID.");
            options.Add(false, "g", "get", false, "Flag to get available privileges for the target process.");
            options.Add(false, "l", "list", false, "Flag to list values for --enable or --disable option.");
            options.Parse(args);

            Execute.Run(options);
        }
    }
}
