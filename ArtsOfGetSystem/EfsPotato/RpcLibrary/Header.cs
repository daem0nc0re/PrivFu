using System;
using System.Runtime.InteropServices;

namespace RpcLibrary
{
    using RPC_STATUS = Int32;

    /*
     * Struct definitions
     */
    [StructLayout(LayoutKind.Sequential)]
    internal struct DEVMODE_CONTAINER
    {
        public int cbBuf;
        public IntPtr /* BYTE* */ pDevMode;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_CLIENT_INTERFACE
    {
        public uint Length;
        public RPC_SYNTAX_IDENTIFIER InterfaceId;
        public RPC_SYNTAX_IDENTIFIER TransferSyntax;
        public IntPtr /* PRPC_DISPATCH_TABLE */ DispatchTable;
        public uint RpcProtseqEndpointCount;
        public IntPtr /* PRPC_PROTSEQ_ENDPOINT */ RpcProtseqEndpoint;
        public UIntPtr Reserved;
        public IntPtr InterpreterInfo;
        public uint Flags;

        public RPC_CLIENT_INTERFACE(
            RPC_SYNTAX_IDENTIFIER _InterfaseId,
            RPC_SYNTAX_IDENTIFIER _TransferSyntax,
            IntPtr _InterpreterInfo)
        {
            Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
            InterfaceId = _InterfaseId;
            TransferSyntax = _TransferSyntax;
            DispatchTable = IntPtr.Zero;
            RpcProtseqEndpointCount = 0u;
            RpcProtseqEndpoint = IntPtr.Zero;
            Reserved = UIntPtr.Zero;
            InterpreterInfo = _InterpreterInfo;
            Flags = 0x02000000u;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_IF_ID_VECTOR
    {
        public uint Count;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public IntPtr[] /* *RPC_IF_ID[] */ IfId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_IF_ID
    {
        public Guid Uuid;
        public ushort VersMajor;
        public ushort VersMinor;
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

    /*
     * Constant definitions
     */
    internal class Consts
    {
        public const RPC_STATUS RPC_S_OK = 0;
    }
}
