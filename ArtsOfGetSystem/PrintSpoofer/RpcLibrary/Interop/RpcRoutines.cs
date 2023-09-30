using System;
using System.Runtime.InteropServices;

namespace RpcLibrary.Interop
{
    using RPC_STATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class RpcRoutines
    {
        public static void Free(IntPtr buffer)
        {
            Marshal.FreeHGlobal(buffer);
        }


        public static IntPtr Malloc(SIZE_T size)
        {
            return Marshal.AllocHGlobal((int)size.ToUInt32());
        }


        public static IntPtr SpoolssBinding(IntPtr pRpcString)
        {
            var hBinding = IntPtr.Zero;
            var rpcString = Marshal.PtrToStringUni(pRpcString);

            try
            {
                do
                {
                    RPC_STATUS rpcStatus = NativeMethods.RpcStringBindingCompose(
                        "12345678-1234-ABCD-EF00-0123456789AB",
                        "ncacn_np",
                        rpcString,
                        @"\pipe\spoolss",
                        null,
                        out IntPtr pStringBinding);

                    if (rpcStatus == 0)
                    {
                        rpcStatus = NativeMethods.RpcBindingFromStringBinding(
                            Marshal.PtrToStringUni(pStringBinding),
                            out hBinding);
                        NativeMethods.RpcStringFree(in pStringBinding);

                        if (rpcStatus != 0)
                            hBinding = IntPtr.Zero;
                    }
                } while (false);
            }
            catch (Exception) { }

            return hBinding;
        }


        public static void Unbind(IntPtr pServer, IntPtr hBinding)
        {
            _ = pServer;
            NativeMethods.RpcBindingFree(ref hBinding);
        }
    }
}
