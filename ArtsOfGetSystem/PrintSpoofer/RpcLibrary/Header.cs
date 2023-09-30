using System;
using System.Runtime.InteropServices;

namespace RpcLibrary
{
    /*
     * Enums
     */
    internal enum PRINTER_CHANGE_FLAGS : uint
    {
        ADD_PRINTER = 0x00000001,
        SET_PRINTER = 0x00000002,
        DELETE_PRINTER = 0x00000004,
        FAILED_CONNECTION_PRINTER = 0x00000008,
        PRINTER = 0x000000FF,
        ADD_JOB = 0x00000100,
        SET_JOB = 0x00000200,
        DELETE_JOB = 0x00000400,
        WRITE_JOB = 0x00000800,
        JOB = 0x0000FF00,
        ADD_FORM = 0x00010000,
        SET_FORM = 0x00020000,
        DELETE_FORM = 0x00040000,
        FORM = 0x00070000,
        ADD_PORT = 0x00100000,
        CONFIGURE_PORT = 0x00200000,
        DELETE_PORT = 0x00400000,
        PORT = 0x00700000,
        ADD_PRINT_PROCESSOR = 0x01000000,
        DELETE_PRINT_PROCESSOR = 0x04000000,
        PRINT_PROCESSOR = 0x07000000,
        SERVER = 0x08000000,
        ADD_PRINTER_DRIVER = 0x10000000,
        SET_PRINTER_DRIVER = 0x20000000,
        DELETE_PRINTER_DRIVER = 0x40000000,
        PRINTER_DRIVER = 0x70000000,
        TIMEOUT = 0x80000000,
        ALL = 0x7F77FFFF
    }

    /*
     * Structs
     */
    [StructLayout(LayoutKind.Sequential)]
    internal struct DEVMODE_CONTAINER
    {
        public int cbBuf;
        public IntPtr /* BYTE* */ pDevMode;
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

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_V2_NOTIFY_OPTIONS
    {
        public int Version;
        public int Reserved;
        public int Count;
        public IntPtr /* RPC_V2_NOTIFY_OPTIONS_TYPE* */ pTypes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_V2_NOTIFY_OPTIONS_TYPE
    {
        public ushort Type;
        public ushort Reserved0;
        public int Reserved1;
        public int Reserved2;
        public int Count;
        public IntPtr /* unsigned short* */ pFields;
    }
}
