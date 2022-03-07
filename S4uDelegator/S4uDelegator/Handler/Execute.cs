using System;
using S4uDelegator.Library;

namespace S4uDelegator.Handler
{
    class Execute
    {
        public static void LookupCommand(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            if (!string.IsNullOrEmpty(options.GetValue("domain")) ||
                !string.IsNullOrEmpty(options.GetValue("username")) ||
                !string.IsNullOrEmpty(options.GetValue("sid")))
            {
                Modules.LookupSid(
                    options.GetValue("domain"),
                    options.GetValue("username"),
                    options.GetValue("sid"));
            }
            else
            {
                options.GetHelp();

                Console.WriteLine("[-] Missing account information.\n");
            }
        }


        public static void ReadCommand(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            if (!string.IsNullOrEmpty(options.GetValue("domain")) ||
                !string.IsNullOrEmpty(options.GetValue("username")) ||
                !string.IsNullOrEmpty(options.GetValue("sid")))
            {
                if (!string.IsNullOrEmpty(options.GetValue("path")))
                {
                    Modules.S4uReadFile(
                        options.GetValue("domain"),
                        options.GetValue("username"),
                        options.GetValue("sid"),
                        options.GetValue("path"));
                }
                else
                {
                    options.GetHelp();

                    Console.WriteLine("[-] Missing file path.\n");
                }
            }
            else
            {
                options.GetHelp();

                Console.WriteLine("[-] Missing account information.\n");
            }
        }


        public static void ShellCommand(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            if (!string.IsNullOrEmpty(options.GetValue("username")) ||
                !string.IsNullOrEmpty(options.GetValue("sid")))
            {
                Modules.GetShell(
                    options.GetValue("username"),
                    options.GetValue("sid"));
            }
            else
            {
                options.GetHelp();

                Console.WriteLine("[-] Missing account information.\n");
            }
        }
    }
}
