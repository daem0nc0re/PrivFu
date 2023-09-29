using System;
using System.Runtime.InteropServices;

namespace RpcLibrary.Interop
{
    internal class MsRprnConsts
    {
        public const int TYPE_FORMAT_STRING_SIZE = 47;
        public const int PROC_FORMAT_STRING_SIZE = 105;
        public const int FORMAT_TABLE_LENGTH = 2;

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

        public static readonly ushort[] FormatStringOffsetTable = new ushort[FORMAT_TABLE_LENGTH] { 0, 36 };

        /* RpcEnumPrinters */
        public static readonly MIDL_FRAG2 __midl_frag2 = new MIDL_FRAG2
        {
            frag1 = new NDR64_PROC_FORMAT
            {
                Flags = 0x1080040u,
                StackSize = 0x10u,
                ConstantClientBufferSize = 0x0u,
                ConstantServerBufferSize = 0x8u,
                RpcFlags = 0x0,
                FloatDoubleMask = 0x0,
                NumberOfParams = 0x1,
                ExtensionSize = 0x8
            },
            frag2 = new NDR64_BIND_AND_NOTIFY_EXTENSION
            {
                Binding = new NDR64_BIND_CONTEXT
                {
                    HandleType = 0x72, /* FC64_BIND_PRIMITIVE */
                    Flags = 0x0,
                    StackOffset = 0x0,
                    RoutineIndex = 0x0,
                    Ordinal = 0x0
                },
                NotifyIndex = 0x0
            },
            frag3 = new NDR64_PARAM_FORMAT
            {
                Type = IntPtr.Zero, // Patched with pointer to __midl_frag18 later
                Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                Reserved = 0x0,
                StackOffset = 0x8
            }
        };
        /* RpcOpenPrinter */
        public static readonly MIDL_FRAG4 __midl_frag4 = new MIDL_FRAG4
        {
            frag1 = new NDR64_PROC_FORMAT
            {
                Flags = 0x12C0040u,
                StackSize = 0x30u,
                ConstantClientBufferSize = 0x8u,
                ConstantServerBufferSize = 0x44u,
                RpcFlags = 0x0,
                FloatDoubleMask = 0x0,
                NumberOfParams = 0x6,
                ExtensionSize = 0x8
            },
            frag2 = new NDR64_BIND_AND_NOTIFY_EXTENSION
            {
                Binding = new NDR64_BIND_CONTEXT
                {
                    HandleType = 0x71, /* FC64_BIND_GENERIC */
                    Flags = 0x0,
                    StackOffset = 0x0,
                    RoutineIndex = 0x0,
                    Ordinal = 0x8
                },
                NotifyIndex = 0x0
            },
            frag3 = new NDR64_PARAM_FORMAT
            {
                Type = IntPtr.Zero, // Patched with pointer to __midl_frag9 later
                Attributes = (NDR64_PARAM_FLAGS)0x000B,
                Reserved = 0,
                StackOffset = 0
            },
            frag4 = new NDR64_PARAM_FORMAT
            {
                Type = IntPtr.Zero, // Patched with pointer to __midl_frag8 later
                Attributes = (NDR64_PARAM_FLAGS)0x0110,
                Reserved = 0,
                StackOffset = 0x8
            },
            frag5 = new NDR64_PARAM_FORMAT
            {
                Type = IntPtr.Zero, // Patched with pointer to __midl_frag9 later
                Attributes = (NDR64_PARAM_FLAGS)0x000B,
                Reserved = 0,
                StackOffset = 0x10
            },
            frag6 = new NDR64_PARAM_FORMAT
            {
                Type = IntPtr.Zero, // Patched with pointer to __midl_frag12 later
                Attributes = (NDR64_PARAM_FLAGS)0x010B,
                Reserved = 0,
                StackOffset = 0x18
            },
            frag7 = new NDR64_PARAM_FORMAT
            {
                Type = IntPtr.Zero, // Patched with pointer to __midl_frag18 later
                Attributes = (NDR64_PARAM_FLAGS)0x00C8,
                Reserved = 0,
                StackOffset = 0x20
            },
            frag8 = new NDR64_PARAM_FORMAT
            {
                Type = IntPtr.Zero, // Patched with pointer to __midl_frag18 later
                Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                Reserved = 0,
                StackOffset = 0x28
            }
        };
        public static readonly MIDL_FRAG8 __midl_frag8 = new MIDL_FRAG8
        {
            FormatCode = 0x70, /* FC64_BIND_CONTEXT */
            ContextFlags = 0xA0,
            RundownRoutineIndex = 0,
            Ordinal = 0
        };
        public static readonly MIDL_FRAG9 __midl_frag9 = new MIDL_FRAG9
        {
            FormatCode = 0x21, /* FC64_UP */
            Flags = 0,
            Reserved = 0,
            Pointee = IntPtr.Zero // Patched with pointer to __midl_frag10 later
        };
        public static readonly MIDL_FRAG10 __midl_frag10 = new MIDL_FRAG10
        {
            Header = new NDR64_STRING_HEADER_FORMAT
            {
                FormatCode = 0x64, /* FC64_CONF_WCHAR_STRING */
                Flags = 0,
                ElementSize = 2
            }
        };
        public static readonly MIDL_FRAG12 __midl_frag12 = new MIDL_FRAG12
        {
            frag1 = new NDR64_BOGUS_STRUCTURE_HEADER_FORMAT
            {
                FormatCode = 0x35, /* FC64_FORCED_BOGUS_STRUCT */
                Alignment = 7,
                Flags = (NDR64_STRUCTURE_FLAGS)3,
                Reserved = 0,
                MemorySize = 0x10,
                OriginalMemberLayout = IntPtr.Zero,
                OriginalPointerLayout = IntPtr.Zero,
                PointerLayout = IntPtr.Zero // Patched with pointer to __midl_frag16 later
            },
            frag2 = new MIDL_FRAG12_INNER
            {
                frag1 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x5, /* FC64_INT32 */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2 = new NDR64_MEMPAD_FORMAT
                {
                    FormatCode = 0x90, /* FC64_STRUCTPADN */
                    Reserved1 = 0,
                    MemPad = 4,
                    Reserved2 = 0
                },
                frag3 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x14, /* FC64_POINTER */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag4 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x93, /* FC64_END */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                }
            }
        };
        public static readonly MIDL_FRAG13 __midl_frag13 = new MIDL_FRAG13
        {
            frag1 = new NDR64_CONF_ARRAY_HEADER_FORMAT
            {
                FormatCode = 0x41, /* FC64_CONF_ARRAY */
                Alignment = 0,
                Flags = (NDR64_ARRAY_FLAGS)0,
                Reserved = 0,
                ElementSize = 1,
                ConfDescriptor = IntPtr.Zero // Patched with pointer to __midl_frag14 later
            },
            frag2 = new NDR64_ARRAY_ELEMENT_INFO
            {
                ElementMemSize = 1,
                Element = IntPtr.Zero // Patched with pointer to __midl_frag15 later
            }
        };
        public static readonly MIDL_FRAG14 __midl_frag14 = new MIDL_FRAG14
        {
            frag1 = 1,
            frag2 = new NDR64_EXPR_VAR
            {
                ExprType = 3, /* FC_EXPR_VAR */
                VarType = 6, /* FC64_UINT32 */
                Reserved = 0,
                Offset = 0
            }
        };

        public static readonly MIDL_FRAG15 __midl_frag15 = new MIDL_FRAG15
        {
            frag1 = 0x2 /* FC64_INT8 */
        };
        public static readonly MIDL_FRAG16 __midl_frag16 = new MIDL_FRAG16
        {
            frag1 = new NDR64_POINTER_FORMAT
            {
                FormatCode = 0x21, /* FC64_UP */
                Reserved = 0,
                Flags = 0x20,
                Pointee = IntPtr.Zero // Patched with pointer to __midl_frag13 later
            }
        };
        public static readonly MIDL_FRAG18 __midl_frag18 = new MIDL_FRAG18
        {
            frag1 = 0x5 /* FC64_INT32 */
        };

        public static readonly MIDL_PROC_FORMAT_STRING ProcFormatString = new MIDL_PROC_FORMAT_STRING
        {
            Pad = 0,
            Format = new byte[PROC_FORMAT_STRING_SIZE]
            {
                /*  0 */ 0x00,
                /*  1 */ 0x48,
                /*  2 */ 0x00, 0x00, 0x00, 0x00, /* 0 */
                /*  6 */ 0x00, 0x00, /* 0 */
                /*  8 */ 0x10, 0x00, /* X64 Stack size/offset = 16 */
                /* 10 */ 0x32, /* FC_BIND_PRIMITIVE */
                /* 11 */ 0x00, /* 0 */
                /* 12 */ 0x00, 0x00, /* X64 Stack size/offset = 0 */
                /* 14 */ 0x00, 0x00, /* 0 */
                /* 16 */ 0x08, 0x00, /* 8 */
                /* 18 */ 0x44, /* Oi2 Flags:  has return, has ext, */
                /* 19 */ 0x1, /* 1 */
                /* 20 */ 0xa, /* 10 */
                /* 21 */ 0x1, /* Ext Flags:  new corr desc, */
                /* 22 */ 0x00, 0x00, /* 0 */
                /* 24 */ 0x00, 0x00, /* 0 */
                /* 26 */ 0x00, 0x00, /* 0 */
                /* 28 */ 0x00, 0x00, /* 0 */
                /* Return value */
                /* 30 */ 0x70, 0x00, /* Flags:  out, return, base type, */
                /* 32 */ 0x08, 0x00, /* X64 Stack size/offset = 8 */
                /* 34 */ 0x08, /* FC_LONG */
                /* 35 */ 0x00, /* 0 */
                /* Procedure RpcOpenPrinter */
                /* 36 */ 0x00, /* 0 */
                /* 37 */ 0x48, /* Old Flags:  */
                /* 38 */ 0x00, 0x00, 0x00, 0x00, /* 0 */
                /* 42 */ 0x01, 0x00, /* 1 */
                /* 44 */ 0x30, 0x00, /* X64 Stack size/offset = 48 */
                /* 46 */ 0x31, /* FC_BIND_GENERIC */
                /* 47 */ 0x08, /* 8 */
                /* 48 */ 0x00, 0x00, /* X64 Stack size/offset = 0 */
                /* 50 */ 0x0, /* 0 */
                /* 51 */ 0x5c, /* FC_PAD */
                /* 52 */ 0x08, 0x00, /* 8 */
                /* 54 */ 0x40, 0x00, /* 64 */
                /* 56 */ 0x46, /* Oi2 Flags:  clt must size, has return, has ext, */
                /* 57 */ 0x06, /* 6 */
                /* 58 */ 0x0a, /* 10 */
                /* 59 */ 0x05, /* Ext Flags:  new corr desc, srv corr check, */
                /* 60 */ 0x00, 0x00, /* 0 */
                /* 62 */ 0x01, 0x00, /* 1 */
                /* 64 */ 0x00, 0x00, /* 0 */
                /* 66 */ 0x00, 0x00, /* 0 */
                /* Parameter pPrinterName */
                /* 68 */ 0x0b, 0x00, /* Flags:  must size, must free, in, */
                /* 70 */ 0x00, 0x00, /* X64 Stack size/offset = 0 */
                /* 72 */ 0x02, 0x00, /* Type Offset=2 */
                /* Parameter pHandle */
                /* 74 */ 0x10, 0x01, /* Flags:  out, simple ref, */
                /* 76 */ 0x08, 0x00, /* X64 Stack size/offset = 8 */
                /* 78 */ 0x0a, 0x00, /* Type Offset=10 */
                /* Parameter pDatatype */
                /* 80 */ 0x0b, 0x00, /* Flags:  must size, must free, in, */
                /* 82 */ 0x10, 0x00, /* X64 Stack size/offset = 16 */
                /* 84 */ 0x02, 0x00, /* Type Offset=2 */
                /* Parameter pDevModeContainer */
                /* 86 */ 0x0b, 0x01, /* Flags:  must size, must free, in, simple ref, */
                /* 88 */ 0x18, 0x00, /* X64 Stack size/offset = 24 */
                /* 90 */ 0x1e, 0x00, /* Type Offset=30 */
                /* Parameter AccessRequired */
                /* 92 */ 0x48, 0x00, /* Flags:  in, base type, */
                /* 94 */ 0x20, 0x00, /* X64 Stack size/offset = 32 */
                /* 96 */ 0x08, /* FC_LONG */
                /* 97 */ 0x00, /* 0 */
                /* Return value */
                /* 98 */ 0x70, 0x00, /* Flags:  out, return, base type, */
                /* 100 */ 0x28, 0x00, /* X64 Stack size/offset = 40 */
                /* 102 */ 0x08, /* FC_LONG */
                /* 103 */ 0x0, /* 0 */
                /* 104 */ 0x00
            }
        };
        public static readonly MIDL_TYPE_FORMAT_STRING TypeFormatString = new MIDL_TYPE_FORMAT_STRING
        {
            Pad = 0,
            Format = new byte[TYPE_FORMAT_STRING_SIZE]
            {
                /*  0 */ 0x00, 0x00,
                /*  2 */ 0x12, 0x08, /* FC_UP [simple_pointer] */
                /*  4 */ 0x25, /* FC_C_WSTRING */
                /*  5 */ 0x5C, /* FC_PAD */
                /*  6 */ 0x11, 0x04, /* FC_RP [alloced_on_stack] */
                /*  8 */ 0x02, 0x00, /* Offset= 2 (10) */
                /* 10 */ 0x30, /* FC_BIND_CONTEXT */
                /* 11 */ 0xA0, /* Ctxt flags:  via ptr, out, */
                /* 12 */ 0x00, /* 0 */
                /* 12 */ 0x00, /* 0 */
                /* 14 */ 0x11, 0x00, /* FC_RP */
                /* 16 */ 0x0E, 0x00, /* Offset= 14 (30) */
                /* 18 */ 0x1B, /* FC_CARRAY */
                /* 19 */ 0x00, /* 0 */
                /* 20 */ 0x01, 0x00, /* 1 */
                /* 22 */ 0x19, /* Corr desc:  field pointer, FC_ULONG */
                /* 23 */ 0x00, /*  */
                /* 24 */ 0x00, 0x00, /* 0 */
                /* 26 */ 0x01, 0x00, /* Corr flags:  early, */
                /* 28 */ 0x01, /* FC_BYTE */
                /* 20 */ 0x5B, /* FC_END */
                /* 30 */ 0x1A, /* FC_BOGUS_STRUCT */
                /* 31 */ 0x03, /* 3 */
                /* 32 */ 0x10, 0x00, /* 16 */
                /* 34 */ 0x00, 0x00, /* 0 */
                /* 36 */ 0x06, 0x00, /* Offset= 6 (42) */
                /* 38 */ 0x08, /* FC_LONG */
                /* 39 */ 0x40, /* FC_STRUCTPAD4 */
                /* 40 */ 0x36, /* FC_POINTER */
                /* 41 */ 0x5B, /* FC_END */
                /* 42 */ 0x12, 0x20, /* FC_UP [maybenull_sizeis] */
                /* 44 */ 0xE6, 0xFF, /* Offset= -26 (18) */
                /* 46 */ 0x00
            }
        };
    }
}
