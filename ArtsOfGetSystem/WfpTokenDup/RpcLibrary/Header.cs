using System;
using System.Runtime.InteropServices;

namespace RpcLibrary
{
    using RPC_STATUS = Int32;

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

    internal class Consts
    {
        public const RPC_STATUS RPC_SUCCESS = 0;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_SYNTAX_IDENTIFIER
    {
        public Guid SyntaxGUID;
        public RPC_VERSION SyntaxVersion;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_VERSION
    {
        public ushort MajorVersion;
        public ushort MinorVersion;
    }
}
