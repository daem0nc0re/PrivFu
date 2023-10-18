using System;
using RpcLibrary.Interop;

namespace RpcLibrary
{
    using RPC_STATUS = Int32;

    internal class RpcHelpers
    {
        public static RPC_STATUS CloseBindingHandle(ref IntPtr hBinding)
        {
            return NativeMethods.RpcBindingFree(ref hBinding);
        }
    }
}
