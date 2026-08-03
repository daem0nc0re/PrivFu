using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SystemServiceExec.Library
{
    internal class Globals
    {
        public static string ServiceName { get; } = "SystemServiceExecSvc";
        public static bool IsServiceCreated { get; set; } = false;
        public static bool IsServiceDeleted { get; set; } = false;
    }
}
