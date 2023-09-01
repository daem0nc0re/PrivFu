using System;
using System.Runtime.InteropServices;

namespace RpcLibrary
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct DEVMODE_CONTAINER
    {
        public int cbBuf;
        public IntPtr /* BYTE* */ pDevMode;
    }
}
