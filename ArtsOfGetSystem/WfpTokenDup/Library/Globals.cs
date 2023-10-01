using System;

namespace WfpTokenDup.Library
{
    internal class Globals
    {
        public static IntPtr WfpAleHandle { get; set; } = IntPtr.Zero;
        public static IntPtr FetchedToken { get; set; } = IntPtr.Zero;
        public static IntPtr StartNotifyEventHandle { get; set; } = IntPtr.Zero;
        public static IntPtr EndNotifyEventHandle { get; set; } = IntPtr.Zero;
    }
}
