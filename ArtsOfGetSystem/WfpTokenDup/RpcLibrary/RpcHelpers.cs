using System;
using System.Runtime.InteropServices;
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

                if (rpcStatus != Consts.RPC_SUCCESS)
                    break;

                rpcStatus = NativeMethods.RpcBindingFromStringBinding(
                    pStringBinding,
                    out hBinding);
                NativeMethods.RpcStringFree(in pStringBinding);

                if (rpcStatus != Consts.RPC_SUCCESS)
                    hBinding = IntPtr.Zero;
            } while (false);

            return hBinding;
        }


        public static IntPtr ConnectToRpcServer(IntPtr hInterface, string endpoint)
        {
            IntPtr hBinding = GetBindingHandle(endpoint);

            if (hBinding != IntPtr.Zero)
            {
                RPC_STATUS rpcStatus = NativeMethods.RpcEpResolveBinding(
                    hBinding,
                    hInterface);

                if (rpcStatus != Consts.RPC_SUCCESS)
                {
                    NativeMethods.RpcBindingFree(ref hBinding);
                    hBinding = IntPtr.Zero;
                }
            }

            return hBinding;
        }


        public static bool VerifyInterfaceEndpoint(
            string endpoint,
            RPC_SYNTAX_IDENTIFIER interfaceId)
        {
            RPC_STATUS rpcStatus;
            var status = false;
            IntPtr hBinding = GetBindingHandle(endpoint);

            if (hBinding == IntPtr.Zero)
                return false;

            rpcStatus = NativeMethods.RpcMgmtInqIfIds(hBinding, out IntPtr pIfIdVector);

            if (rpcStatus == Consts.RPC_SUCCESS)
            {
                var nCount = (uint)Marshal.ReadInt32(pIfIdVector);

                for (var idx = 0; idx < nCount; idx++)
                {
                    var info = (RPC_IF_ID)Marshal.PtrToStructure(
                        Marshal.ReadIntPtr(pIfIdVector, IntPtr.Size * (idx + 1)),
                        typeof(RPC_IF_ID));

                    status = info.Uuid.Equals(interfaceId.SyntaxGUID) &&
                        (info.VersMajor == interfaceId.SyntaxVersion.MajorVersion) &&
                        (info.VersMinor == interfaceId.SyntaxVersion.MinorVersion);

                    if (status)
                        break;
                }

                NativeMethods.RpcIfIdVectorFree(in pIfIdVector);
            }

            NativeMethods.RpcBindingFree(ref hBinding);

            return status;
        }
    }
}
