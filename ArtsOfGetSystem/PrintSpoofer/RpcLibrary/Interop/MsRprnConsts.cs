using System;
using System.Runtime.InteropServices;

namespace RpcLibrary.Interop
{
    internal class MsRprnConsts
    {
        public const int FORMAT_TABLE_LENGTH = 66;
        public const int TYPE_FORMAT_STRING_SIZE = 135;
        public const int PROC_FORMAT_STRING_SIZE = 2383;

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

        public static readonly ushort[] FormatStringOffsetTable = new ushort[FORMAT_TABLE_LENGTH]
        {
            0,
            36,
            104,
            140,
            176,
            212,
            248,
            284,
            320,
            356,
            392,
            428,
            464,
            500,
            536,
            572,
            608,
            644,
            680,
            716,
            752,
            788,
            824,
            860,
            896,
            932,
            968,
            1004,
            1040,
            1076,
            1120,
            1156,
            1192,
            1228,
            1264,
            1300,
            1336,
            1372,
            1402,
            1432,
            1468,
            1504,
            1540,
            1576,
            1606,
            1636,
            1666,
            1702,
            1738,
            1774,
            1804,
            1834,
            1870,
            1906,
            1942,
            1972,
            2002,
            2038,
            2068,
            2104,
            2140,
            2176,
            2212,
            2248,
            2278,
            2308
        };

        public static readonly MIDL_PROC_FORMAT_STRING ProcFormatString = new MIDL_PROC_FORMAT_STRING
        {
            Pad = 0,
            Format = new byte[PROC_FORMAT_STRING_SIZE]
            {
                /* Procedure RpcEnumPrinters (Offset = 0) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x00, 0x00,             /* 0 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 30) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcOpenPrinter (Offset = 36) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x01, 0x00,             /* 1 */
                0x30, 0x00,             /* X64 Stack size/offset = 48 */
                0x31,                   /* FC_BIND_GENERIC */
                0x08,                   /* 8 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00,                   /* 0 */
                0x5C,                   /* FC_PAD */
                0x08, 0x00,             /* 8 */
                0x40, 0x00,             /* 64 */
                0x46,                   /* Oi2 Flags:  clt must size, has return, has ext, */
                0x06,                   /* 6 */
                0x0A,                   /* 10 */
                0x05,                   /* Ext Flags:  new corr desc, srv corr check, */
                0x00, 0x00,             /* 0 */
                0x01, 0x00,             /* 1 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Parameter pPrinterName (Offset = 68) */
                0x0B, 0x00,             /* Flags:  must size, must free, in, */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x02, 0x00,             /* Type Offset=2 */
                /* Parameter pHandle (Offset = 74) */
                0x10, 0x01,             /* Flags:  out, simple ref, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x0A, 0x00,             /* Type Offset=10 */
                /* Parameter pDatatype (Offset = 80) */
                0x0B, 0x00,             /* Flags:  must size, must free, in, */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x02, 0x00,             /* Type Offset=2 */
                /* Parameter pDevModeContainer (Offset = 86) */
                0x0B, 0x01,             /* Flags:  must size, must free, in, simple ref, */
                0x18, 0x00,             /* X64 Stack size/offset = 24 */
                0x1E, 0x00,             /* Type Offset=30 */
                /* Parameter AccessRequired (Offset = 92) */
                0x48, 0x00,             /* Flags:  in, base type, */
                0x20, 0x00,             /* X64 Stack size/offset = 32 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Return value (Offset = 98) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x28, 0x00,             /* X64 Stack size/offset = 40 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcSetJob (Offset = 104) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x02, 0x00,             /* 2 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 134) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcGetJob (Offset = 140) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x03, 0x00,             /* 3 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 170) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcEnumJobs (Offset = 176) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x04, 0x00,             /* 4 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 206) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcAddPrinter (Offset = 212) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x05, 0x00,             /* 5 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 242) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcDeletePrinter (Offset = 248) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x06, 0x00,             /* 6 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 278) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcSetPrinter (Offset = 284) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x07, 0x00,             /* 7 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 314) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcGetPrinter (Offset = 320) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x08, 0x00,             /* 8 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 350) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcAddPrinterDriver (Offset = 356) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x09, 0x00,             /* 9 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 386) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcEnumPrinterDrivers (Offset = 392) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x0A, 0x00,             /* 10 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 422) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcGetPrinterDriver (Offset = 428) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x0B, 0x00,             /* 11 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 458) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcGetPrinterDriverDirectory (Offset = 464) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x0C, 0x00,             /* 12 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 494) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcDeletePrinterDriver (Offset = 500) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x0D, 0x00,             /* 13 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 530) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcAddPrintProcessor (Offset = 536) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x0E, 0x00,             /* 14 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 566) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcEnumPrintProcessors (Offset = 572) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x0F, 0x00,             /* 15 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 602) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcGetPrintProcessorDirectory (Offset = 608) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x10, 0x00,             /* 16 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 638) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcStartDocPrinter (Offset = 644) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x11, 0x00,             /* 17 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 674) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcStartPagePrinter (Offset = 680) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x12, 0x00,             /* 18 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 710) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcWritePrinter (Offset = 716) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x13, 0x00,             /* 19 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 746) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcEndPagePrinter (Offset = 752) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x14, 0x00,             /* 20 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 782) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcAbortPrinter (Offset = 788) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x15, 0x00,             /* 21 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 818) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcReadPrinter (Offset = 824) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x16, 0x00,             /* 22 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 854) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcEndDocPrinter (Offset = 860) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x17, 0x00,             /* 23 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 890) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcAddJob (Offset = 896) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x18, 0x00,             /* 24 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 926) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcScheduleJob (Offset = 932) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x19, 0x00,             /* 25 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 962) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcGetPrinterData (Offset = 968) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x1A, 0x00,             /* 26 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 998) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcSetPrinterData (Offset = 1004) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x1B, 0x00,             /* 27 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1034) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcWaitForPrinterChange (Offset = 1040) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x1C, 0x00,             /* 28 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1070) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcClosePrinter (Offset = 1076) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x1D, 0x00,             /* 29 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x30,                   /* FC_BIND_CONTEXT */
                0xE0,                   /* Ctxt flags:  via ptr, in, out, */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00,                   /* 0 */
                0x00,                   /* 0 */
                0x38, 0x00,             /* 56 */
                0x40, 0x00,             /* 64 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x02,                   /* 2 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Parameter phPrinter (Offset = 1108) */
                0x18, 0x01,             /* Flags:  in, out, simple ref, */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x32, 0x00,             /* Type Offset=50 */
                /* Return value (Offset = 1114) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcAddForm (Offset = 1120)*/
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x1E, 0x00,             /* 30 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1150) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcDeleteForm (Offset = 1156) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x1F, 0x00,             /* 31 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1186) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcGetForm (Offset = 1192) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x20, 0x00,             /* 32 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1222) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcSetForm (Offset = 1228) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x21, 0x00,             /* 33 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1258) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcEnumForms (Offset = 1264) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x22, 0x00,             /* 34 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1294) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcEnumPorts (Offset = 1300) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x23, 0x00,             /* 35 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1330) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcEnumMonitors (Offset = 1336) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x24, 0x00,             /* 36 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1336) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure Opnum37NotUsedOnWire (Offset = 1372) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x25, 0x00,             /* 37 */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x40,                   /* Oi2 Flags:  has ext, */
                0x00,                   /* 0 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Procedure Opnum38NotUsedOnWire (Offset = 1402) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x26, 0x00,             /* 38 */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x40,                   /* Oi2 Flags:  has ext, */
                0x00,                   /* 0 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Procedure RpcDeletePort (Offset = 1432) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x27, 0x00,             /* 39 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1462) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcCreatePrinterIC (Offset = 1468) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x28, 0x00,             /* 40 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1498) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcPlayGdiScriptOnPrinterIC (Offset = 1504) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x29, 0x00,             /* 41 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1534) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcDeletePrinterIC (Offset = 1540) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x2A, 0x00,             /* 42 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1570) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure Opnum43NotUsedOnWire (Offset = 1576) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x2B, 0x00,             /* 43 */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x40,                   /* Oi2 Flags:  has ext, */
                0x00,                   /* 0 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Procedure Opnum44NotUsedOnWire (Offset = 1606) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x2C, 0x00,             /* 44 */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x40,                   /* Oi2 Flags:  has ext, */
                0x00,                   /* 0 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Procedure Opnum45NotUsedOnWire (Offset = 1636) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x2D, 0x00,             /* 45 */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x40,                   /* Oi2 Flags:  has ext, */
                0x00,                   /* 0 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Procedure RpcAddMonitor (Offset = 1666) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x2E, 0x00,             /* 46 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1696) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcDeleteMonitor (Offset = 1702) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x2F, 0x00,             /* 47 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1732) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcDeletePrintProcessor (Offset = 1738) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x30, 0x00,             /* 48 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1768) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure Opnum49NotUsedOnWire (Offset = 1774) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x31, 0x00,             /* 49 */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x40,                   /* Oi2 Flags:  has ext, */
                0x00,                   /* 0 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Procedure Opnum50NotUsedOnWire (Offset = 1804) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x32, 0x00,             /* 50 */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x40,                   /* Oi2 Flags:  has ext, */
                0x00,                   /* 0 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Procedure RpcEnumPrintProcessorDatatypes (Offset = 1834) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x33, 0x00,             /* 51 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1864) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcResetPrinter (Offset = 1870) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x34, 0x00,             /* 52 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1900) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcGetPrinterDriver2 (Offset = 1906) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x35, 0x00,             /* 53 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 1936) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure Opnum54NotUsedOnWire (Offset = 1942) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x36, 0x00,             /* 54 */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x40,                   /* Oi2 Flags:  has ext, */
                0x00,                   /* 0 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Procedure Opnum55NotUsedOnWire (Offset = 1972) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x37, 0x00,             /* 55 */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x40,                   /* Oi2 Flags:  has ext, */
                0x00,                   /* 0 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Procedure RpcFindClosePrinterChangeNotification (Offset = 2002) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x38, 0x00,             /* 56 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 2032) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure Opnum57NotUsedOnWire (Offset = 2038) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x39, 0x00,             /* 57 */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x40,                   /* Oi2 Flags:  has ext, */
                0x00,                   /* 0 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Procedure RpcReplyOpenPrinter (Offset = 2068) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x3A, 0x00,             /* 58 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 2098) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcRouterReplyPrinter (Offset = 2104) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x3B, 0x00,             /* 59 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 2134) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcReplyClosePrinter (Offset = 2140) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x3C, 0x00,             /* 60 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 2170) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcAddPortEx (Offset = 2176) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x3D, 0x00,             /* 61 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 2206) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure RpcRemoteFindFirstPrinterChangeNotification (Offset = 2212) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x3E, 0x00,             /* 62 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x08, 0x00,             /* 8 */
                0x44,                   /* Oi2 Flags:  has return, has ext, */
                0x01,                   /* 1 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Return value (Offset = 2242) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure Opnum63NotUsedOnWire (Offset = 2246) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x3F, 0x00,             /* 63 */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x40,                   /* Oi2 Flags:  has ext, */
                0x00,                   /* 0 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Procedure Opnum64NotUsedOnWire (Offset = 2278) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x40, 0x00,             /* 64 */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x40,                   /* Oi2 Flags:  has ext, */
                0x00,                   /* 0 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Procedure RpcRemoteFindFirstPrinterChangeNotificationEx (Offset = 2308) */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x41, 0x00,             /* 65 */
                0x38, 0x00,             /* X64 Stack size/offset = 56 */
                0x30,                   /* FC_BIND_CONTEXT */
                0x40,                   /* Ctxt flags:  in, */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00,                   /* 0 */
                0x00,                   /* 0 */
                0x3C, 0x00,             /* 60 */
                0x08, 0x00,             /* 8 */
                0x46,                   /* Oi2 Flags:  clt must size, has return, has ext, */
                0x07,                   /* 7 */
                0x0A,                   /* 10 */
                0x05,                   /* Ext Flags:  new corr desc, srv corr check, */
                0x00, 0x00,             /* 0 */
                0x01, 0x00,             /* 1 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Parameter hPrinter (Offset = 2340) */
                0x08, 0x00,             /* Flags:  in, */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x36, 0x00,             /* Type Offset=54 */
                /* Parameter fdwFlags (Offset = 2346) */
                0x48, 0x00,             /* Flags:  in, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Parameter fdwOptions (Offset = 2352) */
                0x48, 0x00,             /* Flags:  in, base type, */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Parameter pszLocalMachine (Offset = 2358) */
                0x0B, 0x00,             /* Flags:  must size, must free, in, */
                0x18, 0x00,             /* X64 Stack size/offset = 24 */
                0x02, 0x00,             /* Type Offset=2 */
                /* Parameter dwPrinterLocal (Offset = 2364) */
                0x48, 0x00,             /* Flags:  in, base type, */
                0x20, 0x00,             /* X64 Stack size/offset = 32 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Parameter pOptions (Offset = 2370) */
                0x0B, 0x00,             /* Flags:  must size, must free, in, */
                0x28, 0x00,             /* X64 Stack size/offset = 40 */
                0x3A, 0x00,             /* Type Offset=58 */
                /* Return value (Offset = 2376) */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x30, 0x00,             /* X64 Stack size/offset = 48 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
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
                0x12, 0x08, /* FC_UP [simple_pointer] */
                /*  4 */    
                0x25,       /* FC_C_WSTRING */
                0x5C,       /* FC_PAD */
                /*  6 */    
                0x11, 0x04, /* FC_RP [alloced_on_stack] */
                0x02, 0x00, /* Offset= 2 (10) */
                0x30,       /* FC_BIND_CONTEXT */
                0xA0,       /* Ctxt flags:  via ptr, out, */
                0x00,       /* 0 */
                0x00,       /* 0 */
                /* 14 */
                0x11, 0x00, /* FC_RP */
                0x0E, 0x00, /* Offset= 14 (30) */
                /* 18 */    
                0x1B,       /* FC_CARRAY */
                0x00,       /* 0 */
                0x01, 0x00, /* 1 */
                0x19,       /* Corr desc:  field pointer, FC_ULONG */
                0x00,       /*  */
                0x00, 0x00, /* 0 */
                0x01, 0x00, /* Corr flags:  early, */
                0x01,       /* FC_BYTE */
                0x5B,       /* FC_END */
                /* 30 */    
                0x1A,       /* FC_BOGUS_STRUCT */
                0x03,       /* 3 */
                0x10, 0x00, /* 16 */
                0x00, 0x00, /* 0 */
                0x06, 0x00, /* Offset= 6 (42) */
                0x08,       /* FC_LONG */
                0x40,       /* FC_STRUCTPAD4 */
                0x36,       /* FC_POINTER */
                0x5B,       /* FC_END */
                /* 42 */    
                0x12, 0x20, /* FC_UP [maybenull_sizeis] */
                0xE6, 0xFF, /* Offset= -26 (18) */
                /* 46 */    
                0x11, 0x04, /* FC_RP [alloced_on_stack] */
                0x02, 0x00, /* Offset= 2 (50) */
                0x30,       /* FC_BIND_CONTEXT */
                0xE1,       /* Ctxt flags:  via ptr, in, out, can't be null */
                0x00,       /* 0 */
                0x00,       /* 0 */
                0x30,       /* FC_BIND_CONTEXT */
                0x41,       /* Ctxt flags:  in, can't be null */
                0x00,       /* 0 */
                0x00,       /* 0 */
                /* 58 */    
                0x12, 0x00, /* FC_UP */
                0x38, 0x00, /* Offset= 56 (116) */
                /* 62 */    
                0x1B,       /* FC_CARRAY */
                0x01,       /* 1 */
                0x02, 0x00, /* 2 */
                0x19,       /* Corr desc:  field pointer, FC_ULONG */
                0x00,       /*  */
                0x0C, 0x00, /* 12 */
                0x01, 0x00, /* Corr flags:  early, */
                0x06,       /* FC_SHORT */
                0x5B,       /* FC_END */
                /* 74 */    
                0x1A,       /* FC_BOGUS_STRUCT */
                0x03,       /* 3 */
                0x18, 0x00, /* 24 */
                0x00, 0x00, /* 0 */
                0x0A, 0x00, /* Offset= 10 (90) */
                0x06,       /* FC_SHORT */
                0x06,       /* FC_SHORT */
                0x08,       /* FC_LONG */
                0x08,       /* FC_LONG */
                0x08,       /* FC_LONG */
                0x36,       /* FC_POINTER */
                0x5C,       /* FC_PAD */
                0x5B,       /* FC_END */
                /* 90 */    
                0x12, 0x20, /* FC_UP [maybenull_sizeis] */
                0xE2, 0xFF, /* Offset= -30 (62) */
                /* 94 */    
                0x21,       /* FC_BOGUS_ARRAY */
                0x03,       /* 3 */
                0x00, 0x00, /* 0 */
                0x19,       /* Corr desc:  field pointer, FC_ULONG */
                0x00,       /*  */
                0x08, 0x00, /* 8 */
                0x01, 0x00, /* Corr flags:  early, */
                0xFF, 0xFF, 0xFF, 0xFF,    /* -1 */
                0x00, 0x00, /* Corr flags:  */
                0x4C,       /* FC_EMBEDDED_COMPLEX */
                0x00,       /* 0 */
                0xDA, 0xFF, /* Offset= -38 (74) */
                0x5C,       /* FC_PAD */
                0x5B,       /* FC_END */
                /* 116 */    
                0x1A,       /* FC_BOGUS_STRUCT */
                0x03,       /* 3 */
                0x18, 0x00, /* 24 */
                0x00, 0x00, /* 0 */
                0x08, 0x00, /* Offset= 8 (130) */
                0x08,       /* FC_LONG */
                0x08,       /* FC_LONG */
                0x08,       /* FC_LONG */
                0x40,       /* FC_STRUCTPAD4 */
                0x36,       /* FC_POINTER */
                0x5B,       /* FC_END */
                /* 130 */    
                0x12, 0x20, /* FC_UP [maybenull_sizeis] */
                0xDA, 0xFF, /* Offset= -38 (94) */
                0x00
            }
        };
    }
}
