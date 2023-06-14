using System;

namespace NamedPipeImpersonation.Library
{
    internal class Globals
    {
        public static bool isPipeConnected = false;
        public static IntPtr hService = IntPtr.Zero;
        public static readonly string serviceName = "PrivFuPipeSvc";
        public static int timeout = 3000;
    }
}
