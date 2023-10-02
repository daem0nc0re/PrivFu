using System;

namespace WfpTokenDup.Library
{
    internal class Globals
    {
        public static IntPtr WfpAleHandle { get; set; } = IntPtr.Zero;
        public static IntPtr SessionToken { get; set; } = IntPtr.Zero;
        public static IntPtr StartNotifyEventHandle { get; set; } = IntPtr.Zero;
        public static IntPtr ExitNotifyEventHandle { get; set; } = IntPtr.Zero;
        public static int Timeout { get; set; } = 3000;
    }
}
