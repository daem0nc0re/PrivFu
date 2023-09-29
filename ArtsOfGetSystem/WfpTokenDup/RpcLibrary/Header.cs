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

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_IF_ID_VECTOR
    {
        public uint Count;
        public IntPtr /* *RPC_IF_ID[] */ IfId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_IF_ID
    {
        public Guid Uuid;
        public ushort VersMajor;
        public ushort VersMinor;
    }
}
