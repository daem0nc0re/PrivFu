using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using RpcLibrary.Interop;

namespace RpcLibrary
{
    using RPC_STATUS = Int32;

    internal class RpcHelpers
    {
        public static IntPtr ConnectToRpcServer(IntPtr hInterface, string endpoint)
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
                    out string stringBinding);

                if (rpcStatus != Consts.RPC_SUCCESS)
                    break;

                rpcStatus = NativeMethods.RpcBindingFromStringBinding(
                    stringBinding,
                    out hBinding);
                NativeMethods.RpcStringFree(in stringBinding);

                if (rpcStatus != Consts.RPC_SUCCESS)
                {
                    hBinding = IntPtr.Zero;
                    break;
                }

                rpcStatus = NativeMethods.RpcEpResolveBinding(hBinding, hInterface);

                if (rpcStatus != Consts.RPC_SUCCESS)
                {
                    NativeMethods.RpcBindingFree(ref hBinding);
                    hBinding = IntPtr.Zero;
                }
            } while (false);

            return hBinding;
        }
    }
}
