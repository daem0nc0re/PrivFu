using System;
using DesktopShell.Library;

namespace DesktopShell
{
    internal class DesktopShell
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: {0} <0 or 1>\n", AppDomain.CurrentDomain.FriendlyName);
                return;
            }

            int nOption;

            try
            {
                nOption = Convert.ToInt32(args[0], 10);
            }
            catch
            {
                Console.WriteLine("[-] Failed to parse option ID.\n");
                return;
            }

            switch (nOption)
            {
                case 0:
                    Modules.GetShell();
                    break;
                case 1:
                    Modules.GetDesktopShell();
                    break;
                default:
                    Console.WriteLine("[-] Invalid option ID.");
                    break;
            }

            Console.WriteLine();
        }
    }
}
