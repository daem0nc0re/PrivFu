using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using S4uDelegator.Library;

namespace S4uDelegator.Handler
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

            string domain = options.GetValue("domain");
            string name = options.GetValue("name");
            string stringSid = options.GetValue("sid");

            Console.WriteLine();

            if (options.GetFlag("lookup") && options.GetFlag("execute"))
            {
                Console.WriteLine("[-] -l and -x cannot be specifed at a time.");
            }
            else if (options.GetFlag("lookup"))
            {
                Modules.LookupSid(domain, name, stringSid);
            }
            else if (options.GetFlag("execute"))
            {
                var extraSids = new List<string>();

                if (!string.IsNullOrEmpty(options.GetValue("extra")))
                {
                    var sidInputs = options.GetValue("extra").Split(',');

                    for (var idx = 0; idx < sidInputs.Length; idx++)
                    {
                        var sid = sidInputs[idx].Trim().ToUpper();

                        if (extraSids.Contains(sid))
                            continue;

                        if (Regex.IsMatch(sid, @"^S(-[0-9]+)+$", RegexOptions.IgnoreCase))
                            extraSids.Add(sid);
                    }
                }

                Modules.GetShell(options.GetValue("command"), domain, name, stringSid, extraSids.ToArray());
            }
            else
            {
                Console.WriteLine("[-] -l or -x flag must be specified.");
            }

            Console.WriteLine();
        }
    }
}
