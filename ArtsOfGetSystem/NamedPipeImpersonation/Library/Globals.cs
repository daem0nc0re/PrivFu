using System;

namespace NamedPipeImpersonation.Library
{
    internal class Globals
    {
        public static IntPtr hService = IntPtr.Zero;
        public static readonly string serviceName = "PrivFuPipeSvc";
    }
}
