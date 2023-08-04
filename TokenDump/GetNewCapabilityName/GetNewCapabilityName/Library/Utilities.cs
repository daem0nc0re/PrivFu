using System.Collections.Generic;
using System.IO;
using System.Xml;

namespace GetNewCapabilityName.Library
{
    internal class Utilities
    {
        public static List<string> GetCapabilityNamesFromXml(string xmlPath)
        {
            var results = new List<string>();
            try
            {
                var nodePathList = new Dictionary<string, string>();
                string parentNodePath = null;
                var xmlDoc = new XmlDocument();
                xmlDoc.Load(xmlPath);

                foreach (XmlNode xmlNode in xmlDoc)
                {
                    if (xmlNode.GetType() == typeof(XmlElement))
                    {
                        foreach (var entry in Helpers.EnumerateXPath(xmlNode, xmlNode.Name))
                        {
                            if (!nodePathList.ContainsKey(entry.Key))
                                nodePathList.Add(entry.Key, entry.Value);
                        }
                    }
                }

                foreach (var nodePath in nodePathList.Keys)
                {
                    if (Helpers.CompareIgnoreCase(Path.GetFileName(nodePath), "Capabilities"))
                    {
                        parentNodePath = nodePath;
                        break;
                    }
                }

                if (!string.IsNullOrEmpty(parentNodePath))
                {
                    string[] pathNames = parentNodePath.Split('/');
                    XmlNode xmlNode = xmlDoc;

                    for (var idx = 0; idx < pathNames.Length; idx++)
                    {
                        foreach (XmlNode childNode in xmlNode.ChildNodes)
                        {
                            if (Helpers.CompareIgnoreCase(childNode.Name, pathNames[idx]))
                            {
                                xmlNode = childNode;
                                break;
                            }
                        }
                    }

                    foreach (XmlNode childNode in xmlNode.ChildNodes)
                    {
                        try
                        {
                            results.Add(childNode.Attributes["Name"].Value);
                        }
                        catch { }
                    }
                }
            }
            catch { }

            return results;
        }
    }
}
