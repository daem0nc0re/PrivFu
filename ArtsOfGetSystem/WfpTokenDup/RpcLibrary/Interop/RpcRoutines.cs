using System;
using System.Runtime.InteropServices;

namespace RpcLibrary.Interop
{
    using SIZE_T = UIntPtr;

    internal class RpcRoutines
    {
        public static void Free(IntPtr buffer)
        {
            Marshal.FreeHGlobal(buffer);
        }


        public static IntPtr Malloc(SIZE_T size)
        {
            var nSize = (int)size.ToUInt32();
            return Marshal.AllocHGlobal(nSize);
        }


        public static void Unbind(IntPtr pServer, IntPtr hBinding)
        {
            _ = pServer;
            NativeMethods.RpcBindingFree(ref hBinding);
        }
    }
}
