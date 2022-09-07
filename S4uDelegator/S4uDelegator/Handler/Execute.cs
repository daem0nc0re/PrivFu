using System;
using System.Text.RegularExpressions;
using S4uDelegator.Library;

namespace S4uDelegator.Handler
{
    internal class Execute
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
                var groupSids = new string[] { };
                var filter = new Regex(@"^(s|S)(-\d+)+(,(s|S)(-\d+)+)*$");

                if (!string.IsNullOrEmpty(options.GetValue("extra")))
                {
                    if (filter.IsMatch(options.GetValue("extra")))
                    {
                        if (options.GetValue("extra").Contains(","))
                        {
                            groupSids = options.GetValue("extra").Split(',');
                        }
                        else
                        {
                            groupSids = new string[] { options.GetValue("extra") };
                        }
                    }
                    else
                    {
                        Console.WriteLine("\n[!] Specified value for -e option is invalid format.\n");

                        return;
                    }
                }

                Modules.GetShell(
                    options.GetValue("domain"),
                    options.GetValue("username"),
                    options.GetValue("sid"),
                    groupSids);
            }
            else
            {
                options.GetHelp();

                Console.WriteLine("[-] Missing account information.\n");
            }
        }
    }
}
