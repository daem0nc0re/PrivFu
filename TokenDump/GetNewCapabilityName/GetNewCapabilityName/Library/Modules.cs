using System;
using System.Collections.Generic;
using System.Linq;
using GetNewCapabilityName.Interop;

namespace GetNewCapabilityName.Library
{
    internal class Modules
    {
        public static bool GetCapabilityNames()
        {
            var registeredList = new List<string>();
            var capabilities = new List<string>();
            var unregistedList = new List<string>();
            var xmlPath = new List<string>();
            var searchRoots = new List<string>
            {
                Environment.GetEnvironmentVariable("LOCALAPPDATA"),
                string.Format(@"{0}\SystemApps", Environment.GetEnvironmentVariable("WINDIR")),
                @"C:\Program Files\WindowsApps"
            };

            for (var idx = 0; idx < Capabilities.KnownCapabilityNames.Length; idx++)
            {
                registeredList.Add(Capabilities.KnownCapabilityNames[idx].ToUpper());
            }

            foreach (var root in searchRoots)
            {
                Console.WriteLine("[>] Searching AppxManifest.xml from \"{0}\".", root);
                xmlPath.AddRange(Helpers.EnumerateFilesRecursive(root, "appxmanifest.xml"));
            }

            Console.WriteLine("[>] Trying to get capability names from AppxManifest.xml.");

            foreach (var xml in xmlPath)
            {
                capabilities.AddRange(Utilities.GetCapabilityNamesFromXml(xml));
            }

            capabilities = new List<string>(capabilities.Distinct());

            foreach (var capName in capabilities)
            {
                if (!registeredList.Contains(capName.ToUpper()))
                    unregistedList.Add(capName);
            }

            if (unregistedList.Count > 0)
            {
                Console.WriteLine("[*] Got {0} new capability name(s):\n", unregistedList.Count);

                foreach (var capName in unregistedList)
                    Console.WriteLine("    {0}", capName);

                Console.WriteLine();
            }
            else
            {
                Console.WriteLine("[*] Nothing new.");
            }

            Console.WriteLine("[*] Done.");

            return true;
        }
    }
}
