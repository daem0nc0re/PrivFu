using System;
using System.Collections.Generic;
using System.IO;
using System.Xml;

namespace GetNewCapabilityName.Library
{
    internal class Helpers
    {
        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        public static List<string> EnumerateFilesRecursive(string directoryPath, string pattern)
        {
            var results = new List<string>();

            try
            {
                var directories = Directory.GetDirectories(directoryPath);
                var files = Directory.EnumerateFiles(directoryPath, pattern, SearchOption.TopDirectoryOnly);

                foreach (var file in files)
                    results.Add(file);

                foreach (var dir in directories)
                {
                    results.AddRange(EnumerateFilesRecursive(dir, pattern));
                }
            }
            catch (System.UnauthorizedAccessException) { }
            catch (PathTooLongException) { }

            return results;
        }


        public static Dictionary<string, string> EnumerateXPath(XmlNode xmlNode, string rootNodePath)
        {
            var results = new Dictionary<string, string>();

            if (!results.ContainsKey(rootNodePath))
                results.Add(rootNodePath, xmlNode.NamespaceURI);

            if (xmlNode.HasChildNodes)
            {
                foreach (XmlNode childNode in xmlNode.ChildNodes)
                {
                    var childNodePath = string.Format(@"{0}/{1}", rootNodePath, childNode.Name);

                    if (!results.ContainsKey(childNodePath))
                        results.Add(childNodePath, childNode.NamespaceURI);

                    foreach (var entry in EnumerateXPath(childNode, childNodePath))
                    {
                        if (!results.ContainsKey(entry.Key))
                            results.Add(entry.Key, entry.Value);
                    }
                }
            }

            return results;
        }
    }
}
