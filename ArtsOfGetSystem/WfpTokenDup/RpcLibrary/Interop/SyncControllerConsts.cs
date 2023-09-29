using System;
using System.Runtime.InteropServices;

namespace RpcLibrary.Interop
{
    internal class SyncControllerConsts
    {
        public const int TYPE_FORMAT_STRING_SIZE = 11;
        public const int PROC_FORMAT_STRING_SIZE = 661;
        public const int FORMAT_TABLE_LENGTH = 18;

        [StructLayout(LayoutKind.Sequential)]
        internal struct SYNCCTRL_MIDL_PROC_FORMAT_STRING
        {
            public short Pad;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = PROC_FORMAT_STRING_SIZE)]
            public byte[] Format;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SYNCCTRL_MIDL_TYPE_FORMAT_STRING
        {
            public short Pad;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = TYPE_FORMAT_STRING_SIZE)]
            public byte[] Format;
        }

        public static readonly ushort[] FormatStringOffsetTable = new ushort[FORMAT_TABLE_LENGTH]
        {
            0,
            36,
            72,
            108,
            144,
            180,
            216,
            252,
            288,
            324,
            360,
            396,
            432,
            468,
            516,
            552,
            588,
            624
        };
        public static readonly SYNCCTRL_MIDL_PROC_FORMAT_STRING ProcFormatString = new SYNCCTRL_MIDL_PROC_FORMAT_STRING
        {
            Pad = 0,
            Format = new byte[PROC_FORMAT_STRING_SIZE]
            {
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
				/* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure AccountsMgmtRpcDeleteAccount */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x01, 0x00,             /* 1 */
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
                /* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
				/* Procedure AccountsMgmtRpcConvertWebAccountIdFromAppSpecificId */
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
				/* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
				/* Procedure AccountsMgmtRpcConvertWebAccountIdToAppSpecificId */
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
                /* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
				/* Procedure AccountsMgmtRpcSyncAccount */
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
				/* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure AccountsMgmtRpcSyncAccountAndWaitForCompletion */
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
                /* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure AccountsMgmtRpcQueryAccountProperties */
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
                /* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure AccountsMgmtRpcSaveAccountProperties */
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
                /* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure AccountsMgmtRpcEnumAccounts */
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
                /* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure AccountsMgmtRpcAdviseAccount */
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
                /* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure AccountsMgmtRpcUnadviseAccount */
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
                /* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure AccountsMgmtRpcGetNotifications */
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
                /* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure AccountsMgmtRpcDiscoverExchangeServerConfig */
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
                /* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure AccountsMgmtRpcDiscoverExchangeServerAuthType */
                0x00,                   /* 0 */
                0x48,                   /* Old Flags:  */
                0x00, 0x00, 0x00, 0x00, /* 0 */
                0x0D, 0x00,             /* 13 */
                0x20, 0x00,             /* X64 Stack size/offset = 32 */
                0x32,                   /* FC_BIND_PRIMITIVE */
                0x00,                   /* 0 */
                0x00, 0x00,             /* X64 Stack size/offset = 0 */
                0x00, 0x00,             /* 0 */
                0x24, 0x00,             /* 36 */
                0x46,                   /* Oi2 Flags:  clt must size, has return, has ext, */
                0x03,                   /* 3 */
                0x0A,                   /* 10 */
                0x01,                   /* Ext Flags:  new corr desc, */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                0x00, 0x00,             /* 0 */
                /* Parameter ServerAddress */
                0x0B, 0x01,             /* Flags:  must size, must free, in, simple ref, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x04, 0x00,             /* Type Offset=4 */
                /* Parameter IntOut */
                0x50, 0x21,             /* Flags:  out, base type, simple ref, srv alloc size=8 */
                0x10, 0x00,             /* X64 Stack size/offset = 16 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x18, 0x00,             /* X64 Stack size/offset = 24 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure AccountsMgmtRpcVerifyExchangeMailBoxTokenAuth */
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
                /* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure AccountsMgmtRpcDiscoverInternetMailServerConfig */
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
                /* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure AccountsMgmtRpcCancelDiscoverInternetMailServerConfig */
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
                /* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                /* Procedure AccountsMgmtRpcMayIgnoreInvalidServerCertificate */
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
                /* Return value */
                0x70, 0x00,             /* Flags:  out, return, base type, */
                0x08, 0x00,             /* X64 Stack size/offset = 8 */
                0x08,                   /* FC_LONG */
                0x00,                   /* 0 */
                0x00
            }
        };
        public static readonly SYNCCTRL_MIDL_TYPE_FORMAT_STRING TypeFormatString = new SYNCCTRL_MIDL_TYPE_FORMAT_STRING
        {
            Pad = 0,
            Format = new byte[TYPE_FORMAT_STRING_SIZE]
            {
                0x00, 0x00, /* 0 */
                0x11, 0x08, /* FC_RP [simple_pointer] */
                0x25,       /* FC_C_WSTRING */
                0x5C,       /* FC_PAD */
                0x11, 0x0C, /* FC_RP [alloced_on_stack] [simple_pointer] */
                0x08,       /* FC_LONG */
                0x5C,       /* FC_PAD */
                0x00
            }
        };
    }
}
