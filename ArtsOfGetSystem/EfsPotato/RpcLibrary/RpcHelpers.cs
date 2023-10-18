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


        public static IntPtr GetBindingHandle(string endpoint)
        {
            RPC_STATUS rpcStatus;
            IntPtr hBinding = IntPtr.Zero;

            do
            {
                rpcStatus = NativeMethods.RpcStringBindingCompose(
                    null,
                    "ncalrpc",
                    null,
                    endpoint,
                    null,
                    out IntPtr pStringBinding);

                if (rpcStatus != Consts.RPC_S_OK)
                    break;

                rpcStatus = NativeMethods.RpcBindingFromStringBinding(
                    pStringBinding,
                    out hBinding);
                NativeMethods.RpcStringFree(in pStringBinding);

                if (rpcStatus != Consts.RPC_S_OK)
                    hBinding = IntPtr.Zero;
            } while (false);

            return hBinding;
        }
    }
}
