using System.Runtime.InteropServices;

namespace RpcLibrary.Interop
{
    internal class MsEfsrConsts
    {
        public const int FORMAT_TABLE_LENGTH = 45;
        public const int TYPE_FORMAT_STRING_SIZE = 539;
        public const int PROC_FORMAT_STRING_SIZE = 1795;

        [StructLayout(LayoutKind.Sequential)]
        internal struct MIDL_PROC_FORMAT_STRING
        {
            public short Pad;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = PROC_FORMAT_STRING_SIZE)]
            public byte[] Format;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct MIDL_TYPE_FORMAT_STRING
        {
            public short Pad;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = TYPE_FORMAT_STRING_SIZE)]
            public byte[] Format;
        }

        public static readonly MIDL_PROC_FORMAT_STRING ProcFormatString = new MIDL_PROC_FORMAT_STRING
        {
            Pad = 0,
            Format = new byte[PROC_FORMAT_STRING_SIZE]
            {
                /* Procedure EfsRpcOpenFileRaw (Offset = 0) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x28, 0x00, /* X64 Stack size/offset = 40 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x08, 0x00, /* 8 */
                0x40, 0x00, /* 64 */
                0x46,       /* Oi2 Flags:  clt must size, has return, has ext, */
                0x04,       /* 4 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter hContext */
                0x10, 0x01, /* Flags:  out, simple ref, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x06, 0x00, /* Type Offset=6 */
                /* Parameter FileName */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Parameter Flags */
                0x48, 0x00, /* Flags:  in, base type, */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x20, 0x00, /* X64 Stack size/offset = 32 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure EfsRpcReadFileRaw (Offset = 54) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x01, 0x00, /* 1 */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x30,       /* FC_BIND_CONTEXT */
                0x40,       /* Ctxt flags:  in, */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00,       /* 0 */
                0x00,       /* 0 */
                0x24, 0x00, /* 36 */
                0x08, 0x00, /* 8 */
                0x4C,       /* Oi2 Flags:  has return, has pipes, has ext, */
                0x03,       /* 3 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter hContext */
                0x08, 0x00, /* Flags:  in, */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x0E, 0x00, /* Type Offset=14 */
                /* Parameter EfsOutPipe */
                0x14, 0x41, /* Flags:  pipe, out, simple ref, srv alloc size=16 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x18, 0x00, /* Type Offset=24 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure EfsRpcWriteFileRaw (Offset = 104) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x02, 0x00, /* 2 */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x30,       /* FC_BIND_CONTEXT */
                0x40,       /* Ctxt flags:  in, */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00,       /* 0 */
                0x00,       /* 0 */
                0x24, 0x00, /* 36 */
                0x08, 0x00, /* 8 */
                0x4C,       /* Oi2 Flags:  has return, has pipes, has ext, */
                0x03,       /* 3 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter hContext */
                0x08, 0x00, /* Flags:  in, */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x0E, 0x00, /* Type Offset=14 */
                /* Parameter EfsInPipe */
                0x0C, 0x01, /* Flags:  pipe, in, simple ref, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x26, 0x00, /* Type Offset=38 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure EfsRpcCloseRaw (Offset = 154) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x03, 0x00, /* 3 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x30,       /* FC_BIND_CONTEXT */
                0xE0,       /* Ctxt flags:  via ptr, in, out, */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00,       /* 0 */
                0x00,       /* 0 */
                0x38, 0x00, /* 56 */
                0x38, 0x00, /* 56 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x01,       /* 1 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter hContext */
                0x18, 0x01, /* Flags:  in, out, simple ref, */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x32, 0x00, /* Type Offset=50 */
                /* Procedure EfsRpcEncryptFileSrv (Offset = 192) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x04, 0x00, /* 4 */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x08, 0x00, /* 8 */
                0x46,       /* Oi2 Flags:  clt must size, has return, has ext, */
                0x02,       /* 2 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter FileName */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure EfsRpcDecryptFileSrv (Offset = 234) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x05, 0x00, /* 5 */
                0x20, 0x00, /* X64 Stack size/offset = 32 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x08, 0x00, /* 8 */
                0x08, 0x00, /* 8 */
                0x46,       /* Oi2 Flags:  clt must size, has return, has ext, */
                0x03,       /* 3 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter FileName */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Parameter OpenFlag */
                0x48, 0x00, /* Flags:  in, base type, */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure EfsRpcQueryUsersOnFile (Offset = 282) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x06, 0x00, /* 6 */
                0x20, 0x00, /* X64 Stack size/offset = 32 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x08, 0x00, /* 8 */
                0x47,       /* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
                0x03,       /* 3 */
                0x0A,       /* 10 */
                0x43,       /* Ext Flags:  new corr desc, clt corr check, has range on conformance */
                0x01, 0x00, /* 1 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter FileName */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Parameter Users */
                0x13, 0x20, /* Flags:  must size, must free, out, srv alloc size=8 */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0x36, 0x00, /* Type Offset=54 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure EfsRpcQueryRecoveryAgents (Offset = 330) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x07, 0x00, /* 7 */
                0x20, 0x00, /* X64 Stack size/offset = 32 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x08, 0x00, /* 8 */
                0x47,       /* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
                0x03,       /* 3 */
                0x0A,       /* 10 */
                0x43,       /* Ext Flags:  new corr desc, clt corr check, has range on conformance */
                0x01, 0x00, /* 1 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter FileName */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Parameter RecoveryAgents */
                0x13, 0x20, /* Flags:  must size, must free, out, srv alloc size=8 */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0x36, 0x00, /* Type Offset=54 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure EfsRpcRemoveUsersFromFile (Offset = 378) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x08, 0x00, /* 8 */
                0x20, 0x00, /* X64 Stack size/offset = 32 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x08, 0x00, /* 8 */
                0x46,       /* Oi2 Flags:  clt must size, has return, has ext, */
                0x03,       /* 3 */
                0x0A,       /* 10 */
                0x45,       /* Ext Flags:  new corr desc, srv corr check, has range on conformance */
                0x00, 0x00, /* 0 */
                0x01, 0x00, /* 1 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter FileName */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Parameter Users */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0xDC, 0x00, /* Type Offset=220 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure EfsRpcAddUsersToFile (Offset = 426) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x09, 0x00, /* 9 */
                0x20, 0x00, /* X64 Stack size/offset = 32 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x08, 0x00, /* 8 */
                0x46,       /* Oi2 Flags:  clt must size, has return, has ext, */
                0x03,       /* 3 */
                0x0A,       /* 10 */
                0x45,       /* Ext Flags:  new corr desc, srv corr check, has range on conformance */
                0x00, 0x00, /* 0 */
                0x01, 0x00, /* 1 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter FileName */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Parameter EncryptionCertificates */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0x5A, 0x01, /* Type Offset=346 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure Opnum10NotUsedOnWire (Offset = 474) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x0A, 0x00, /* 10 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure EfsRpcNotSupported (Offset = 504) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x0B, 0x00, /* 11 */
                0x40, 0x00, /* X64 Stack size/offset = 64 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x18, 0x00, /* 24 */
                0x08, 0x00, /* 8 */
                0x46,       /* Oi2 Flags:  clt must size, has return, has ext, */
                0x07,       /* 7 */
                0x0A,       /* 10 */
                0x45,       /* Ext Flags:  new corr desc, srv corr check, has range on conformance */
                0x00, 0x00, /* 0 */
                0x01, 0x00, /* 1 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter Reserved1 */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Parameter Reserved2 */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Parameter dwReserved1 */
                0x48, 0x00, /* Flags:  in, base type, */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Parameter dwReserved2 */
                0x48, 0x00, /* Flags:  in, base type, */
                0x20, 0x00, /* X64 Stack size/offset = 32 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Parameter Reserved */
                0x0B, 0x00, /* Flags:  must size, must free, in, */
                0x28, 0x00, /* X64 Stack size/offset = 40 */
                0x6A, 0x01, /* Type Offset=362 */
                /* Parameter bReserved */
                0x48, 0x00, /* Flags:  in, base type, */
                0x30, 0x00, /* X64 Stack size/offset = 48 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x38, 0x00, /* X64 Stack size/offset = 56 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure EfsRpcFileKeyInfo (Offset = 576) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x0C, 0x00, /* 12 */
                0x28, 0x00, /* X64 Stack size/offset = 40 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x08, 0x00, /* 8 */
                0x08, 0x00, /* 8 */
                0x47,       /* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
                0x04,       /* 4 */
                0x0A,       /* 10 */
                0x43,       /* Ext Flags:  new corr desc, clt corr check, has range on conformance */
                0x01, 0x00, /* 1 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter FileName */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Parameter InfoClass */
                0x48, 0x00, /* Flags:  in, base type, */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Parameter KeyInfo */
                0x13, 0x20, /* Flags:  must size, must free, out, srv alloc size=8 */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x94, 0x01, /* Type Offset=404 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x20, 0x00, /* X64 Stack size/offset = 32 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure EfsRpcDuplicateEncryptionInfoFile (Offset = 630) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x0D, 0x00, /* 13 */
                0x40, 0x00, /* X64 Stack size/offset = 64 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x18, 0x00, /* 24 */
                0x08, 0x00, /* 8 */
                0x46,       /* Oi2 Flags:  clt must size, has return, has ext, */
                0x07,       /* 7 */
                0x0A,       /* 10 */
                0x45,       /* Ext Flags:  new corr desc, srv corr check, has range on conformance */
                0x00, 0x00, /* 0 */
                0x01, 0x00, /* 1 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter SrcFileName */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Parameter DestFileName */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Parameter dwCreationDisposition */
                0x48, 0x00, /* Flags:  in, base type, */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Parameter dwAttributes */
                0x48, 0x00, /* Flags:  in, base type, */
                0x20, 0x00, /* X64 Stack size/offset = 32 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Parameter RelativeSD */
                0x0B, 0x00, /* Flags:  must size, must free, in, */
                0x28, 0x00, /* X64 Stack size/offset = 40 */
                0x6A, 0x01, /* Type Offset=362 */
                /* Parameter bInheritHandle */
                0x48, 0x00, /* Flags:  in, base type, */
                0x30, 0x00, /* X64 Stack size/offset = 48 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x38, 0x00, /* X64 Stack size/offset = 56 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure Opnum14NotUsedOnWire (Offset = 702) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x0E, 0x00, /* 14 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure EfsRpcAddUsersToFileEx (Offset = 732) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x0F, 0x00, /* 15 */
                0x30, 0x00, /* X64 Stack size/offset = 48 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x08, 0x00, /* 8 */
                0x08, 0x00, /* 8 */
                0x46,       /* Oi2 Flags:  clt must size, has return, has ext, */
                0x05,       /* 5 */
                0x0A,       /* 10 */
                0x45,       /* Ext Flags:  new corr desc, srv corr check, has range on conformance */
                0x00, 0x00, /* 0 */
                0x01, 0x00, /* 1 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter dwFlags */
                0x48, 0x00, /* Flags:  in, base type, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Parameter Reserved */
                0x0B, 0x00, /* Flags:  must size, must free, in, */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0x6A, 0x01, /* Type Offset=362 */
                /* Parameter FileName */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Parameter EncryptionCertificates */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x20, 0x00, /* X64 Stack size/offset = 32 */
                0x5A, 0x01, /* Type Offset=346 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x28, 0x00, /* X64 Stack size/offset = 40 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure EfsRpcFileKeyInfoEx (Offset = 792) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x10, 0x00, /* 16 */
                0x38, 0x00, /* X64 Stack size/offset = 56 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x10, 0x00, /* 16 */
                0x08, 0x00, /* 8 */
                0x47,       /* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
                0x06,       /* 6 */
                0x0A,       /* 10 */
                0x47,       /* Ext Flags:  new corr desc, clt corr check, srv corr check, has range on conformance */
                0x01, 0x00, /* 1 */
                0x01, 0x00, /* 1 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter dwFileKeyInfoFlags */
                0x48, 0x00, /* Flags:  in, base type, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Parameter Reserved */
                0x0B, 0x00, /* Flags:  must size, must free, in, */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0x6A, 0x01, /* Type Offset=362 */
                /* Parameter FileName */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Parameter InfoClass */
                0x48, 0x00, /* Flags:  in, base type, */
                0x20, 0x00, /* X64 Stack size/offset = 32 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Parameter KeyInfo */
                0x13, 0x20, /* Flags:  must size, must free, out, srv alloc size=8 */
                0x28, 0x00, /* X64 Stack size/offset = 40 */
                0x94, 0x01, /* Type Offset=404 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x30, 0x00, /* X64 Stack size/offset = 48 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure Opnum17NotUsedOnWire (Offset = 858) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x11, 0x00, /* 17 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure EfsRpcGetEncryptedFileMetadata (Offset = 888) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x12, 0x00, /* 18 */
                0x20, 0x00, /* X64 Stack size/offset = 32 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x08, 0x00, /* 8 */
                0x47,       /* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
                0x03,       /* 3 */
                0x0A,       /* 10 */
                0x43,       /* Ext Flags:  new corr desc, clt corr check, has range on conformance */
                0x01, 0x00, /* 1 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter FileName */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Parameter EfsStreamBlob */
                0x13, 0x20, /* Flags:  must size, must free, out, srv alloc size=8 */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0x94, 0x01, /* Type Offset=404 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure EfsRpcSetEncryptedFileMetadata (Offset = 936) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x13, 0x00, /* 19 */
                0x30, 0x00, /* X64 Stack size/offset = 48 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x08, 0x00, /* 8 */
                0x46,       /* Oi2 Flags:  clt must size, has return, has ext, */
                0x05,       /* 5 */
                0x0A,       /* 10 */
                0x45,       /* Ext Flags:  new corr desc, srv corr check, has range on conformance */
                0x00, 0x00, /* 0 */
                0x01, 0x00, /* 1 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter FileName */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Parameter OldEfsStreamBlob */
                0x0B, 0x00, /* Flags:  must size, must free, in, */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0x6A, 0x01, /* Type Offset=362 */
                /* Parameter NewEfsStreamBlob */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x84, 0x01, /* Type Offset=388 */
                /* Parameter NewEfsSignature */
                0x0B, 0x00, /* Flags:  must size, must free, in, */
                0x20, 0x00, /* X64 Stack size/offset = 32 */
                0x9C, 0x01, /* Type Offset=412 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x28, 0x00, /* X64 Stack size/offset = 40 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure EfsRpcFlushEfsCache (Offset = 996) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x14, 0x00, /* 20 */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x08, 0x00, /* 8 */
                0x44,       /* Oi2 Flags:  has return, has ext, */
                0x01,       /* 1 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure EfsRpcEncryptFileExSrv (Offset = 1032) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x15, 0x00, /* 21 */
                0x28, 0x00, /* X64 Stack size/offset = 40 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x08, 0x00, /* 8 */
                0x08, 0x00, /* 8 */
                0x46,       /* Oi2 Flags:  clt must size, has return, has ext, */
                0x04,       /* 4 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter FileName */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Parameter ProtectorDescriptor */
                0x0B, 0x00, /* Flags:  must size, must free, in, */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0xBA, 0x01, /* Type Offset=442 */
                /* Parameter Flags */
                0x48, 0x00, /* Flags:  in, base type, */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x20, 0x00, /* X64 Stack size/offset = 32 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure EfsRpcQueryProtectors (Offset = 1086) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x16, 0x00, /* 22 */
                0x20, 0x00, /* X64 Stack size/offset = 32 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x08, 0x00, /* 8 */
                0x47,       /* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
                0x03,       /* 3 */
                0x0A,       /* 10 */
                0x43,       /* Ext Flags:  new corr desc, clt corr check, has range on conformance */
                0x01, 0x00, /* 1 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Parameter FileName */
                0x0B, 0x01, /* Flags:  must size, must free, in, simple ref, */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x0C, 0x00, /* Type Offset=12 */
                /* Parameter ppProtectorList */
                0x13, 0x20, /* Flags:  must size, must free, out, srv alloc size=8 */
                0x10, 0x00, /* X64 Stack size/offset = 16 */
                0xBE, 0x01, /* Type Offset=446 */
                /* Return value */
                0x70, 0x00, /* Flags:  out, return, base type, */
                0x18, 0x00, /* X64 Stack size/offset = 24 */
                0x08,       /* FC_LONG */
                0x00,       /* 0 */
                /* Procedure Opnum23NotUsedOnWire (Offset = 1134) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x17, 0x00, /* 23 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum24NotUsedOnWire (Offset = 1164) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x18, 0x00, /* 24 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum25NotUsedOnWire (Offset = 1194) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x19, 0x00, /* 25 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum26NotUsedOnWire (Offset = 1224) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x1A, 0x00, /* 26 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum27NotUsedOnWire (Offset = 1254) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x1B, 0x00, /* 27 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum28NotUsedOnWire (Offset = 1284) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x1C, 0x00, /* 28 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum29NotUsedOnWire (Offset = 1314) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x1D, 0x00, /* 29 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum30NotUsedOnWire (Offset = 1344) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x1E, 0x00, /* 30 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum31NotUsedOnWire (Offset = 1374) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x1F, 0x00, /* 31 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum32NotUsedOnWire (Offset = 1404) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x20, 0x00, /* 32 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum33NotUsedOnWire (Offset = 1434) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x21, 0x00, /* 33 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum34NotUsedOnWire (Offset = 1464) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x22, 0x00, /* 34 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum35NotUsedOnWire (Offset = 1494) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x23, 0x00, /* 35 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum36NotUsedOnWire (Offset = 1524) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x24, 0x00, /* 36 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum37NotUsedOnWire (Offset = 1554) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x25, 0x00, /* 37 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum38NotUsedOnWire (Offset = 1584) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x26, 0x00, /* 38 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum39NotUsedOnWire (Offset = 1614) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x27, 0x00, /* 39 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum40NotUsedOnWire (Offset = 1644) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x28, 0x00, /* 40 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum41NotUsedOnWire (Offset = 1674) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x29, 0x00, /* 41 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum42NotUsedOnWire (Offset = 1704) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x2A, 0x00, /* 42 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum43NotUsedOnWire (Offset = 1734) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x2B, 0x00, /* 43 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                /* Procedure Opnum44NotUsedOnWire (Offset = 1764) */
                0x00,       /* 0 */
                0x48,       /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x2C, 0x00, /* 44 */
                0x08, 0x00, /* X64 Stack size/offset = 8 */
                0x32,       /* FC_BIND_PRIMITIVE */
                0x00,       /* 0 */
                0x00, 0x00, /* X64 Stack size/offset = 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x40,       /* Oi2 Flags:  has ext, */
                0x00,       /* 0 */
                0x0A,       /* 10 */
                0x41,       /* Ext Flags:  new corr desc, has range on conformance */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00, 0x00, /* 0 */
                0x00
            }
        };
        public static readonly MIDL_TYPE_FORMAT_STRING TypeFormatString = new MIDL_TYPE_FORMAT_STRING
        {
            Pad = 0,
            Format = new byte[TYPE_FORMAT_STRING_SIZE]
            {
                0x00, 0x00, /* 0 */
            /*  2 */    
            0x11, 0x04, /* FC_RP [alloced_on_stack] */
            0x02, 0x00, /* Offset= 2 (6) */
            0x30,       /* FC_BIND_CONTEXT */
            0xA0,       /* Ctxt flags:  via ptr, out, */
            0x00,       /* 0 */
            0x00,       /* 0 */
            /* 10 */    
            0x11, 0x08, /* FC_RP [simple_pointer] */
            /* 12 */    
            0x25,       /* FC_C_WSTRING */
            0x5C,       /* FC_PAD */
            0x30,       /* FC_BIND_CONTEXT */
            0x41,       /* Ctxt flags:  in, can't be null */
            0x00,       /* 0 */
            0x00,       /* 0 */
            /* 18 */    
            0x11, 0x04, /* FC_RP [alloced_on_stack] */
            0x04, 0x00, /* Offset= 4 (24) */
            0x02,       /* FC_CHAR */
            0x5C,       /* FC_PAD */
            0xB5,       /* FC_PIPE */
            0x00,       /* 0 */
            0xFC, 0xFF, /* Offset= -4 (22) */
            0x01, 0x00, /* 1 */
            0x01, 0x00, /* 1 */
            /* 32 */    
            0x11, 0x00, /* FC_RP */
            0x04, 0x00, /* Offset= 4 (38) */
            0x02,       /* FC_CHAR */
            0x5C,       /* FC_PAD */
            0xB5,       /* FC_PIPE */
            0x00,       /* 0 */
            0xFC, 0xFF, /* Offset= -4 (36) */
            0x01, 0x00, /* 1 */
            0x01, 0x00, /* 1 */
            /* 46 */    
            0x11, 0x04, /* FC_RP [alloced_on_stack] */
            0x02, 0x00, /* Offset= 2 (50) */
            0x30,       /* FC_BIND_CONTEXT */
            0xE1,       /* Ctxt flags:  via ptr, in, out, can't be null */
            0x00,       /* 0 */
            0x00,       /* 0 */
            /* 54 */    
            0x11, 0x14, /* FC_RP [alloced_on_stack] [pointer_deref] */
            0x02, 0x00, /* Offset= 2 (58) */
            /* 58 */    
            0x12, 0x00, /* FC_UP */
            0xA0, 0x00, /* Offset= 160 (220) */
            /* 62 */    
            0x1D,       /* FC_SMFARRAY */
            0x00,       /* 0 */
            0x06, 0x00, /* 6 */
            0x02,       /* FC_CHAR */
            0x5B,       /* FC_END */
            /* 68 */    
            0x15,       /* FC_STRUCT */
            0x00,       /* 0 */
            0x06, 0x00, /* 6 */
            0x4C,       /* FC_EMBEDDED_COMPLEX */
            0x00,       /* 0 */
            0xF4, 0xFF, /* Offset= -12 (62) */
            0x5C,       /* FC_PAD */
            0x5B,       /* FC_END */
            /* 78 */    
            0x1B,       /* FC_CARRAY */
            0x03,       /* 3 */
            0x04, 0x00, /* 4 */
            0x04,       /* Corr desc: FC_USMALL */
            0x00,       /*  */
            0xF9, 0xFF, /* -7 */
            0x01, 0x00, /* Corr flags:  early, */
            0x00,
            0x00,       /* 0 */
            0x00, 0x00, 0x00, 0x00, /* 0 */
            0x00, 0x00, 0x00, 0x00, /* 0 */
            0x08,       /* FC_LONG */
            0x5B,       /* FC_END */
            /* 100 */    
            0x17,       /* FC_CSTRUCT */
            0x03,       /* 3 */
            0x08, 0x00, /* 8 */
            0xE6, 0xFF, /* Offset= -26 (78) */
            0x02,       /* FC_CHAR */
            0x02,       /* FC_CHAR */
            0x4C,       /* FC_EMBEDDED_COMPLEX */
            0x00,       /* 0 */
            0xD6, 0xFF, /* Offset= -42 (68) */
            0x5C,       /* FC_PAD */
            0x5B,       /* FC_END */
            /* 114 */    
            0x1B,       /* FC_CARRAY */
            0x00,       /* 0 */
            0x01, 0x00, /* 1 */
            0x19,       /* Corr desc:  field pointer, FC_ULONG */
            0x00,       /*  */
            0x00, 0x00, /* 0 */
            0x11, 0x00, /* Corr flags:  early, */
            0x01, /* correlation range */
            0x00,       /* 0 */
            0x00, 0x00, 0x00, 0x00, /* 0 */
            0x64, 0x00, 0x00, 0x00, /* 100 */
            0x02,       /* FC_CHAR */
            0x5B,       /* FC_END */
            /* 136 */    
            0x1A,       /* FC_BOGUS_STRUCT */
            0x03,       /* 3 */
            0x10, 0x00, /* 16 */
            0x00, 0x00, /* 0 */
            0x06, 0x00, /* Offset= 6 (148) */
            0x08,       /* FC_LONG */
            0x40,       /* FC_STRUCTPAD4 */
            0x36,       /* FC_POINTER */
            0x5B,       /* FC_END */
            /* 148 */    
            0x12, 0x20, /* FC_UP [maybenull_sizeis] */
            0xDC, 0xFF, /* Offset= -36 (114) */
            /* 152 */    
            0x1A,       /* FC_BOGUS_STRUCT */
            0x03,       /* 3 */
            0x20, 0x00, /* 32 */
            0x00, 0x00, /* 0 */
            0x08, 0x00, /* Offset= 8 (166) */
            0x08,       /* FC_LONG */
            0x40,       /* FC_STRUCTPAD4 */
            0x36,       /* FC_POINTER */
            0x36,       /* FC_POINTER */
            0x36,       /* FC_POINTER */
            0x5B,       /* FC_END */
            /* 166 */    
            0x12, 0x00, /* FC_UP */
            0xBC, 0xFF, /* Offset= -68 (100) */
            /* 170 */    
            0x12, 0x00, /* FC_UP */
            0xDC, 0xFF, /* Offset= -36 (136) */
            /* 174 */    
            0x12, 0x08, /* FC_UP [simple_pointer] */
            /* 176 */    
            0x25,       /* FC_C_WSTRING */
            0x5C,       /* FC_PAD */
            /* 178 */    
            0x21,       /* FC_BOGUS_ARRAY */
            0x03,       /* 3 */
            0x00, 0x00, /* 0 */
            0x19,       /* Corr desc:  field pointer, FC_ULONG */
            0x00,       /*  */
            0x00, 0x00, /* 0 */
            0x11, 0x00, /* Corr flags:  early, */
            0x01, /* correlation range */
            0x00,       /* 0 */
            0x00, 0x00, 0x00, 0x00, /* 0 */
            0xF4, 0x01, 0x00, 0x00, /* 500 */
            0xFF, 0xFF, 0xFF, 0xFF, /* -1 */
            0x00, 0x00, /* Corr flags:  */
            0x00,
            0x00,       /* 0 */
            0x00, 0x00, 0x00, 0x00, /* 0 */
            0x00, 0x00, 0x00, 0x00, /* 0 */
            /* 214 */    
            0x12, 0x00, /* FC_UP */
            0xC0, 0xFF, /* Offset= -64 (152) */
            0x5C,       /* FC_PAD */
            0x5B,       /* FC_END */
            /* 220 */    
            0x1A,       /* FC_BOGUS_STRUCT */
            0x03,       /* 3 */
            0x10, 0x00, /* 16 */
            0x00, 0x00, /* 0 */
            0x06, 0x00, /* Offset= 6 (232) */
            0x08,       /* FC_LONG */
            0x40,       /* FC_STRUCTPAD4 */
            0x36,       /* FC_POINTER */
            0x5B,       /* FC_END */
            /* 232 */    
            0x12, 0x20, /* FC_UP [maybenull_sizeis] */
            0xC8, 0xFF, /* Offset= -56 (178) */
            /* 236 */    
            0x11, 0x00, /* FC_RP */
            0xEE, 0xFF, /* Offset= -18 (220) */
            /* 240 */    
            0x11, 0x00, /* FC_RP */
            0x68, 0x00, /* Offset= 104 (346) */
            /* 244 */    
            0x1B,       /* FC_CARRAY */
            0x00,       /* 0 */
            0x01, 0x00, /* 1 */
            0x19,       /* Corr desc:  field pointer, FC_ULONG */
            0x00,       /*  */
            0x04, 0x00, /* 4 */
            0x11, 0x00, /* Corr flags:  early, */
            0x01, /* correlation range */
            0x00,       /* 0 */
            0x00, 0x00, 0x00, 0x00, /* 0 */
            0x00, 0x80, 0x00, 0x00, /* 32768 */
            0x02,       /* FC_CHAR */
            0x5B,       /* FC_END */
            /* 266 */    
            0x1A,       /* FC_BOGUS_STRUCT */
            0x03,       /* 3 */
            0x10, 0x00, /* 16 */
            0x00, 0x00, /* 0 */
            0x06, 0x00, /* Offset= 6 (278) */
            0x08,       /* FC_LONG */
            0x08,       /* FC_LONG */
            0x36,       /* FC_POINTER */
            0x5B,       /* FC_END */
            /* 278 */    
            0x12, 0x20, /* FC_UP [maybenull_sizeis] */
            0xDC, 0xFF, /* Offset= -36 (244) */
            /* 282 */    
            0x1A,       /* FC_BOGUS_STRUCT */
            0x03,       /* 3 */
            0x18, 0x00, /* 24 */
            0x00, 0x00, /* 0 */
            0x08, 0x00, /* Offset= 8 (296) */
            0x08,       /* FC_LONG */
            0x40,       /* FC_STRUCTPAD4 */
            0x36,       /* FC_POINTER */
            0x36,       /* FC_POINTER */
            0x5C,       /* FC_PAD */
            0x5B,       /* FC_END */
            /* 296 */    
            0x12, 0x00, /* FC_UP */
            0x3A, 0xFF, /* Offset= -198 (100) */
            /* 300 */    
            0x12, 0x00, /* FC_UP */
            0xDC, 0xFF, /* Offset= -36 (266) */
            /* 304 */    
            0x21,       /* FC_BOGUS_ARRAY */
            0x03,       /* 3 */
            0x00, 0x00, /* 0 */
            0x19,       /* Corr desc:  field pointer, FC_ULONG */
            0x00,       /*  */
            0x00, 0x00, /* 0 */
            0x11, 0x00, /* Corr flags:  early, */
            0x01, /* correlation range */
            0x00,       /* 0 */
            0x00, 0x00, 0x00, 0x00, /* 0 */
            0xF4, 0x01, 0x00, 0x00, /* 500 */
            0xFF, 0xFF, 0xFF, 0xFF, /* -1 */
            0x00, 0x00, /* Corr flags:  */
            0x00,
            0x00,       /* 0 */
            0x00, 0x00, 0x00, 0x00, /* 0 */
            0x00, 0x00, 0x00, 0x00, /* 0 */
            /* 340 */    
            0x12, 0x00, /* FC_UP */
            0xC4, 0xFF, /* Offset= -60 (282) */
            0x5C,       /* FC_PAD */
            0x5B,       /* FC_END */
            /* 346 */    
            0x1A,       /* FC_BOGUS_STRUCT */
            0x03,       /* 3 */
            0x10, 0x00, /* 16 */
            0x00, 0x00, /* 0 */
            0x06, 0x00, /* Offset= 6 (358) */
            0x08,       /* FC_LONG */
            0x40,       /* FC_STRUCTPAD4 */
            0x36,       /* FC_POINTER */
            0x5B,       /* FC_END */
            /* 358 */    
            0x12, 0x20, /* FC_UP [maybenull_sizeis] */
            0xC8, 0xFF, /* Offset= -56 (304) */
            /* 362 */    
            0x12, 0x00, /* FC_UP */
            0x18, 0x00, /* Offset= 24 (388) */
            /* 366 */    
            0x1B,       /* FC_CARRAY */
            0x00,       /* 0 */
            0x01, 0x00, /* 1 */
            0x19,       /* Corr desc:  field pointer, FC_ULONG */
            0x00,       /*  */
            0x00, 0x00, /* 0 */
            0x11, 0x00, /* Corr flags:  early, */
            0x01, /* correlation range */
            0x00,       /* 0 */
            0x00, 0x00, 0x00, 0x00, /* 0 */
            0x00, 0x10, 0x04, 0x00, /* 266240 */
            0x02,       /* FC_CHAR */
            0x5B,       /* FC_END */
            /* 388 */    
            0x1A,       /* FC_BOGUS_STRUCT */
            0x03,       /* 3 */
            0x10, 0x00, /* 16 */
            0x00, 0x00, /* 0 */
            0x06, 0x00, /* Offset= 6 (400) */
            0x08,       /* FC_LONG */
            0x40,       /* FC_STRUCTPAD4 */
            0x36,       /* FC_POINTER */
            0x5B,       /* FC_END */
            /* 400 */    
            0x12, 0x20, /* FC_UP [maybenull_sizeis] */
            0xDC, 0xFF, /* Offset= -36 (366) */
            /* 404 */    
            0x11, 0x14, /* FC_RP [alloced_on_stack] [pointer_deref] */
            0xD4, 0xFF, /* Offset= -44 (362) */
            /* 408 */    
            0x11, 0x00, /* FC_RP */
            0xEA, 0xFF, /* Offset= -22 (388) */
            /* 412 */    
            0x12, 0x00, /* FC_UP */
            0x02, 0x00, /* Offset= 2 (416) */
            /* 416 */    
            0x1A,       /* FC_BOGUS_STRUCT */
            0x03,       /* 3 */
            0x20, 0x00, /* 32 */
            0x00, 0x00, /* 0 */
            0x08, 0x00, /* Offset= 8 (430) */
            0x08,       /* FC_LONG */
            0x40,       /* FC_STRUCTPAD4 */
            0x36,       /* FC_POINTER */
            0x36,       /* FC_POINTER */
            0x36,       /* FC_POINTER */
            0x5B,       /* FC_END */
            /* 430 */    
            0x12, 0x00, /* FC_UP */
            0x2C, 0xFF, /* Offset= -212 (220) */
            /* 434 */    
            0x12, 0x00, /* FC_UP */
            0x66, 0xFF, /* Offset= -154 (282) */
            /* 438 */    
            0x12, 0x00, /* FC_UP */
            0xCC, 0xFF, /* Offset= -52 (388) */
            /* 442 */    
            0x12, 0x08, /* FC_UP [simple_pointer] */
            /* 444 */    
            0x25,       /* FC_C_WSTRING */
            0x5C,       /* FC_PAD */
            /* 446 */    
            0x11, 0x14, /* FC_RP [alloced_on_stack] [pointer_deref] */
            0x02, 0x00, /* Offset= 2 (450) */
            /* 450 */    
            0x12, 0x10, /* FC_UP [pointer_deref] */
            0x02, 0x00, /* Offset= 2 (454) */
            /* 454 */    
            0x12, 0x00, /* FC_UP */
            0x42, 0x00, /* Offset= 66 (522) */
            /* 458 */    
            0x1A,       /* FC_BOGUS_STRUCT */
            0x03,       /* 3 */
            0x18, 0x00, /* 24 */
            0x00, 0x00, /* 0 */
            0x08, 0x00, /* Offset= 8 (472) */
            0x08,       /* FC_LONG */
            0x40,       /* FC_STRUCTPAD4 */
            0x36,       /* FC_POINTER */
            0x36,       /* FC_POINTER */
            0x5C,       /* FC_PAD */
            0x5B,       /* FC_END */
            /* 472 */    
            0x12, 0x00, /* FC_UP */
            0x8A, 0xFE, /* Offset= -374 (100) */
            /* 476 */    
            0x12, 0x08, /* FC_UP [simple_pointer] */
            /* 478 */    
            0x25,       /* FC_C_WSTRING */
            0x5C,       /* FC_PAD */
            /* 480 */    
            0x21,       /* FC_BOGUS_ARRAY */
            0x03,       /* 3 */
            0x00, 0x00, /* 0 */
            0x19,       /* Corr desc:  field pointer, FC_ULONG */
            0x00,       /*  */
            0x00, 0x00, /* 0 */
            0x01, 0x00, /* Corr flags:  early, */
            0x00,
            0x00,       /* 0 */
            0x00, 0x00, 0x00, 0x00, /* 0 */
            0x00, 0x00, 0x00, 0x00, /* 0 */
            0xFF, 0xFF, 0xFF, 0xFF, /* -1 */
            0x00, 0x00, /* Corr flags:  */
            0x00,
            0x00,       /* 0 */
            0x00, 0x00, 0x00, 0x00, /* 0 */
            0x00, 0x00, 0x00, 0x00, /* 0 */
            /* 516 */    
            0x12, 0x00, /* FC_UP */
            0xC4, 0xFF, /* Offset= -60 (458) */
            0x5C,       /* FC_PAD */
            0x5B,       /* FC_END */
            /* 522 */    
            0x1A,       /* FC_BOGUS_STRUCT */
            0x03,       /* 3 */
            0x10, 0x00, /* 16 */
            0x00, 0x00, /* 0 */
            0x06, 0x00, /* Offset= 6 (534) */
            0x08,       /* FC_LONG */
            0x40,       /* FC_STRUCTPAD4 */
            0x36,       /* FC_POINTER */
            0x5B,       /* FC_END */
            /* 534 */    
            0x12, 0x20, /* FC_UP [maybenull_sizeis] */
            0xC8, 0xFF, /* Offset= -56 (480) */
            0x00
            }
        };
        public static ushort[] FormatStringOffsetTable = new ushort[FORMAT_TABLE_LENGTH]
        {
            0,
            54,
            104,
            154,
            192,
            234,
            282,
            330,
            378,
            426,
            474,
            504,
            576,
            630,
            702,
            732,
            792,
            858,
            888,
            936,
            996,
            1032,
            1086,
            1134,
            1164,
            1194,
            1224,
            1254,
            1284,
            1314,
            1344,
            1374,
            1404,
            1434,
            1464,
            1494,
            1524,
            1554,
            1584,
            1614,
            1644,
            1674,
            1704,
            1734,
            1764
        };
    }
}
