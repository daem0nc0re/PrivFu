using System;
using System.Runtime.InteropServices;
using RpcLibrary.Interop;

namespace RpcLibrary
{
    using SIZE_T = UIntPtr;
    using RPC_STATUS = Int32;

    internal class MsRprn : IDisposable
    {
        private readonly byte[] MidlFrag4 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG4))];
        private readonly byte[] MidlFrag8 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG8))];
        private readonly byte[] MidlFrag12 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG12))];
        private readonly byte[] MidlFrag13 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG13))];
        private readonly byte[] MidlFrag14 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG14))];
        private readonly byte[] MidlFrag15 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG15))];
        private readonly byte[] MidlFrag16 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG16))];
        private readonly byte[] MidlFrag71 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG71))];
        private readonly byte[] MidlFrag73 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG73))];
        private readonly byte[] MidlFrag75 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG75))];
        private readonly byte[] MidlFrag131 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG131))];
        private readonly byte[] MidlFrag134 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG134))];
        private readonly byte[] MidlFrag135 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG135))];
        private readonly byte[] MidlFrag136 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG136))];
        private readonly byte[] MidlFrag138 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG138))];
        private readonly byte[] MidlFrag139 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG139))];
        private readonly byte[] MidlFrag140 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG140))];
        private readonly byte[] MidlFrag141 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG141))];
        private readonly byte[] MidlFrag142 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG142))];
        private readonly byte[] MidlFrag143 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG143))];
        private readonly byte[] MidlFrag144 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG144))];
        private readonly byte[] MidlFrag145 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG145))];
        private readonly byte[] MidlFrag148 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG148))];
        private readonly byte[] MidlFrag149 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG149))];
        private readonly byte[] MidlFrag150 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG150))];
        private readonly byte[] MidlFrag151 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG151))];
        private readonly byte[] MidlFrag152 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG152))];
        private readonly byte[] MidlFrag153 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG153))];
        public readonly IntPtr[] Ndr64ProcTable = new IntPtr[66];

        private readonly IntPtr pProxyInfo = IntPtr.Zero;
        private readonly IntPtr pStubDesc = IntPtr.Zero;
        private readonly IntPtr pBindingRoutinePair = IntPtr.Zero;
        private readonly IntPtr pRpcClientInterface = IntPtr.Zero;
        private readonly IntPtr pRpcTransferSyntax = IntPtr.Zero;
        private readonly IntPtr pRpcProtseqEndpoint = IntPtr.Zero;
        private readonly IntPtr pAutoHandle = IntPtr.Zero;
        private readonly IntPtr pSyntaxInfo = IntPtr.Zero;
        private readonly IntPtr pSequenceName = IntPtr.Zero;
        private readonly IntPtr pEndpointPath = IntPtr.Zero;

        /*
         * Constructor and Destructor
         */
        public MsRprn()
        {
            /*
             * Allocate required buffers
             */
            int nInfoLength = Marshal.SizeOf(typeof(RPC_SYNTAX_IDENTIFIER));
            pRpcTransferSyntax = Marshal.AllocHGlobal(nInfoLength);

            nInfoLength = Marshal.SizeOf(typeof(RPC_PROTSEQ_ENDPOINT));
            pRpcProtseqEndpoint = Marshal.AllocHGlobal(nInfoLength);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_SYNTAX_INFO)) * 2;
            pSyntaxInfo = Marshal.AllocHGlobal(nInfoLength);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_STUBLESS_PROXY_INFO));
            pProxyInfo = Marshal.AllocHGlobal(nInfoLength);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_STUB_DESC));
            pStubDesc = Marshal.AllocHGlobal(nInfoLength);

            nInfoLength = Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
            pRpcClientInterface = Marshal.AllocHGlobal(nInfoLength);

            pAutoHandle = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pAutoHandle, IntPtr.Zero);

            /*
             * Resolve routine APIs
             */
            var bindingRoutinePair = new GENERIC_BINDING_ROUTINE_PAIR
            {
                pfnBind = Marshal.GetFunctionPointerForDelegate((GENERIC_BINDING_ROUTINE)RpcRoutines.SpoolssBinding),
                pfnUnbind = Marshal.GetFunctionPointerForDelegate((GENERIC_UNBIND_ROUTINE)RpcRoutines.Unbind)
            };
            pBindingRoutinePair = Marshal.AllocHGlobal(Marshal.SizeOf(bindingRoutinePair));
            Marshal.StructureToPtr(bindingRoutinePair, pBindingRoutinePair, true);

            /*
             * Build winspool_ProxyInfo
             */
            var midlFrag4 = new MIDL_FRAG4
            {
                /* RpcOpenPrinter */
                /* RpcOpenPrinter Procedure */
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
                        HandleType = 0x71,
                        Flags = 0x0,
                        StackOffset = 0x0,
                        RoutineIndex = 0x0,
                        Ordinal = 0x8
                    },
                    NotifyIndex = 0x0
                },
                /* pPrinterName */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag139, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x000B,
                    Reserved = 0x0,
                    StackOffset= 0x0
                },
                /* pHandle */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag8, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x0110,
                    Reserved = 0x0,
                    StackOffset = 0x8
                },
                /* pDatatype */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag139, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x000B,
                    Reserved = 0x0,
                    StackOffset = 0x10
                },
                /* pDevModeContainer */
                frag6 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag12, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0x0,
                    StackOffset = 0x18
                },
                /* AccessRequired */
                frag7 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag153, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00C8,
                    Reserved = 0x0,
                    StackOffset = 0x20
                },
                /* DWORD */
                frag8 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag153, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0x0,
                    StackOffset = 0x28
                }
            };
            Marshal.StructureToPtr(
                midlFrag4,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag4, 0),
                true);

            var midlFrag8 = new MIDL_FRAG8
            {
                FormatCode = 0x70, /* FC64_BIND_CONTEXT */
                ContextFlags = 0xA0,
                RundownRoutineIndex = 0x0,
                Ordinal = 0x0
            };
            Marshal.StructureToPtr(
                midlFrag8,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag8, 0),
                true);

            var midlFrag12 = new MIDL_FRAG12
            {
                /* DEVMODE_CONTAINER */
                frag1 = new NDR64_BOGUS_STRUCTURE_HEADER_FORMAT
                {
                    FormatCode = 0x35, /* FC64_FORCED_BOGUS_STRUCT */
                    Alignment = 0x7,
                    Flags = (NDR64_STRUCTURE_FLAGS)0x03,
                    Reserve = 0,
                    MemorySize = 0x10,
                    OriginalMemberLayout = IntPtr.Zero,
                    OriginalPointerLayout = IntPtr.Zero,
                    PointerLayout = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag16, 0)
                },
                frag2 = new MIDL_FRAG12_INNER
                {
                    frag1 = new NDR64_SIMPLE_MEMBER_FORMAT
                    {
                        FormatCode = 0x5, /* FC64_INT32 */
                        Reserved1 = 0x0,
                        Reserved2 = 0x0,
                        Reserved3 = 0x0
                    },
                    frag2 = new NDR64_MEMPAD_FORMAT
                    {
                        FormatCode = 0x90, /* FC64_STRUCTPADN */
                        Reserved1 = 0x0,
                        MemPad = 0x4,
                        Reserved2 = 0x0
                    },
                    frag3 = new NDR64_SIMPLE_MEMBER_FORMAT
                    {
                        FormatCode = 0x14, /* FC64_POINTER */
                        Reserved1 = 0x0,
                        Reserved2 = 0x0,
                        Reserved3 = 0x0
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
            Marshal.StructureToPtr(
                midlFrag12,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag12, 0),
                true);

            var midlFrag13 = new MIDL_FRAG13
            {
                frag1 = new NDR64_CONF_ARRAY_HEADER_FORMAT
                {
                    FormatCode = 0x41, /* FC64_CONF_ARRAY */
                    Alignment = 0,
                    Flags = 0,
                    Reserved = 0,
                    ElementSize = 0x1,
                    ConfDescriptor = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag14, 0)
                },
                frag2 = new NDR64_ARRAY_ELEMENT_INFO
                {
                    ElementMemSize = 1,
                    Element = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag15, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag13,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag13, 0),
                true);

            var midlFrag14 = new MIDL_FRAG14
            {
                frag1 = 1u,
                frag2 = new NDR64_EXPR_VAR
                {
                    ExprType = 0x3, /* FC_EXPR_VAR */
                    VarType = 0x6, /* FC64_UINT32 */
                    Reserved = 0,
                    Offset = 0
                }
            };
            Marshal.StructureToPtr(
                midlFrag14,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag14, 0),
                true);

            MidlFrag15[0] = 0x2; /* FC64_INT8 */

            var midlFrag16 = new MIDL_FRAG16
            {
                frag1 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0x20,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag13, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag16,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag16, 0),
                true);

            var midlFrag71 = new MIDL_FRAG71
            {
                /* RpcWaitForPrinterChange Procedure */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x1080040, /* IsIntrepreted, HasReturn, HasExtensions */
                    StackSize = 0x10,
                    ConstantClientBufferSize = 0,
                    ConstantServerBufferSize = 0x8,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x1,
                    ExtensionSize = 0x8
                },
                frag2 = new NDR64_BIND_AND_NOTIFY_EXTENSION
                {
                    Binding = new NDR64_BIND_CONTEXT
                    {
                        HandleType = 0x72, /* FC64_BIND_PRIMITIVE */
                        Flags = 0,
                        StackOffset = 0,
                        RoutineIndex = 0,
                        Ordinal = 0
                    },
                    NotifyIndex = 0
                },
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag153, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x8
                }
            };
            Marshal.StructureToPtr(
                midlFrag71,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                true);

            var midlFrag73 = new MIDL_FRAG73
            {
                /* RpcClosePrinter */
                /* RpcClosePrinter Procedure */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x1080040, /* IsIntrepreted, HasReturn, HasExtensions */
                    StackSize = 0x10,
                    ConstantClientBufferSize = 0x3C,
                    ConstantServerBufferSize = 0x44,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x2,
                    ExtensionSize = 0x8
                },
                frag2 = new NDR64_BIND_AND_NOTIFY_EXTENSION
                {
                    Binding = new NDR64_BIND_CONTEXT
                    {
                        HandleType = 0x70, /* FC64_BIND_CONTEXT */
                        Flags = 0xE0,
                        StackOffset = 0x0,
                        RoutineIndex = 0x0,
                        Ordinal = 0x0
                    },
                    NotifyIndex = 0x0
                },
                /* phPrinter */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag75, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x0118,
                    Reserved = 0,
                    StackOffset = 0x0
                },
                /* DWORD */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag141, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x8
                }
            };
            Marshal.StructureToPtr(
                midlFrag73,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag73, 0),
                true);

            var midlFrag75 = new MIDL_FRAG75
            {
                FormatCode = 0x70, /* FC64_BIND_CONTEXT */
                ContextFlags = 0xE1,
                RundownRoutineIndex = 0,
                Ordinal = 0
            };
            Marshal.StructureToPtr(
                midlFrag75,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag75, 0),
                true);

            var midlFrag131 = new MIDL_FRAG131
            {
                /* RpcRemoteFindFirstPrinterChangeNotification */
                /* RpcRemoteFindFirstPrinterChangeNotification Procedure */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x1080040, /* IsIntrepreted, HasReturn, HasExtensions */
                    StackSize = 0x10,
                    ConstantClientBufferSize = 0x0,
                    ConstantServerBufferSize = 0x8,
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
                        Ordinal = 0x0,
                    },
                    NotifyIndex = 0x0
                },
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag141, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0x0,
                    StackOffset = 0x8
                }
            };
            Marshal.StructureToPtr(
                midlFrag131,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                true);

            var midlFrag134 = new MIDL_FRAG134
            {
                /* Opnum64NotUsedOnWire */
                /* Opnum64NotUsedOnWire Procedure */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x1000040, /* IsIntrepreted, HasExtensions */
                    StackSize = 0x8,
                    ConstantClientBufferSize = 0x0,
                    ConstantServerBufferSize = 0x0,
                    RpcFlags = 0x0,
                    FloatDoubleMask = 0x0,
                    NumberOfParams = 0x0,
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
                        Ordinal = 0x0,
                    },
                    NotifyIndex = 0x0
                }
            };
            Marshal.StructureToPtr(
                midlFrag134,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag134, 0),
                true);

            var midlFrag135 = new MIDL_FRAG135
            {
                /* RpcRemoteFindFirstPrinterChangeNotificationEx */
                /* RpcRemoteFindFirstPrinterChangeNotificationEx Procedure */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x12C0040, /* IsIntrepreted, ClientMustSize, HasReturn, ServerCorrelation, HasExtensions */
                    StackSize = 0x38,
                    ConstantClientBufferSize = 0x3C,
                    ConstantServerBufferSize = 0x8,
                    RpcFlags = 0x0,
                    FloatDoubleMask = 0x0,
                    NumberOfParams = 0x7,
                    ExtensionSize = 0x8
                },
                frag2 = new NDR64_BIND_AND_NOTIFY_EXTENSION
                {
                    Binding = new NDR64_BIND_CONTEXT
                    {
                        HandleType = 0x70, /* FC64_BIND_CONTEXT */
                        Flags = 0x40,
                        StackOffset = 0x0,
                        RoutineIndex = 0x0,
                        Ordinal = 0x0
                    },
                    NotifyIndex = 0x0
                },
                /* hPrinter */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag136, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x0008,
                    Reserved = 0x0,
                    StackOffset = 0x0
                },
                /* fdwFlags */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag138, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00C8,
                    Reserved = 0x0,
                    StackOffset = 0x8
                },
                /* fdwOptions */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag138, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00C8,
                    Reserved = 0x0,
                    StackOffset = 0x10
                },
                /* pszLocalMachine */
                frag6 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag139, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x000B,
                    Reserved = 0x0,
                    StackOffset = 0x18
                },
                /* dwPrinterLocal */
                frag7 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag141, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00C8,
                    Reserved = 0x0,
                    StackOffset = 0x20
                },
                /* pOptions */
                frag8 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag142, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x000B,
                    Reserved = 0x0,
                    StackOffset = 0x28
                },
                /* DWORD */
                frag9 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag153, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0x0,
                    StackOffset = 0x30
                }
            };
            Marshal.StructureToPtr(
                midlFrag135,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag135, 0),
                true);

            var midlFrag136 = new MIDL_FRAG136
            {
                FormatCode = 0x70, /* FC64_BIND_CONTEXT */
                ContextFlags = 0x41,
                RundownRoutineIndex = 0x0,
                Ordinal = 0x0
            };
            Marshal.StructureToPtr(
                midlFrag136,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag136, 0),
                true);

            MidlFrag138[0] = 0x05; /* FC64_INT32 */

            var midlFrag139 = new MIDL_FRAG139
            {
                FormatCode = 0x21, /* FC64_UP */
                Flags = 0x0,
                Reserved = 0x0,
                Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag140, 0)
            };
            Marshal.StructureToPtr(
                midlFrag139,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag139, 0),
                true);

            var midlFrag140 = new MIDL_FRAG140
            {
                /* *wchar_t */
                Header = new NDR64_STRING_HEADER_FORMAT
                {
                    FormatCode = 0x64, /* FC64_CONF_WCHAR_STRING */
                    Flags = 0x0,
                    ElementSize = 0x2
                }
            };
            Marshal.StructureToPtr(
                midlFrag140,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag140, 0),
                true);

            MidlFrag141[0] = 0x05; /* FC64_INT32 */

            var midlFrag142 = new MIDL_FRAG142
            {
                /* *RPC_V2_NOTIFY_OPTIONS */
                FormatCode = 0x21, /* FC64_UP */
                Flags = 0x0,
                Reserved = 0x0,
                Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag143, 0)
            };
            Marshal.StructureToPtr(
                midlFrag142,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag142, 0),
                true);

            var midlFrag143 = new MIDL_FRAG143
            {
                /* RPC_V2_NOTIFY_OPTIONS */
                frag1 = new NDR64_BOGUS_STRUCTURE_HEADER_FORMAT
                {
                    FormatCode = 0x35, /* FC64_FORCED_BOGUS_STRUCT */
                    Alignment = 0x7,
                    Flags = (NDR64_STRUCTURE_FLAGS)0x03,
                    Reserve = 0x0,
                    MemorySize = 0x18,
                    OriginalMemberLayout = IntPtr.Zero,
                    OriginalPointerLayout = IntPtr.Zero,
                    PointerLayout = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag152, 0)
                },
                frag2 = new MIDL_FRAG143_INNER
                {
                    frag1 = new NDR64_SIMPLE_MEMBER_FORMAT
                    {
                        FormatCode = 0x5, /* FC64_INT32 */
                        Reserved1 = 0x0,
                        Reserved2 = 0x0,
                        Reserved3 = 0x0,
                    },
                    frag2 = new NDR64_SIMPLE_MEMBER_FORMAT
                    {
                        FormatCode = 0x5, /* FC64_INT32 */
                        Reserved1 = 0x0,
                        Reserved2 = 0x0,
                        Reserved3 = 0x0,
                    },
                    frag3 = new NDR64_SIMPLE_MEMBER_FORMAT
                    {
                        FormatCode = 0x5, /* FC64_INT32 */
                        Reserved1 = 0x0,
                        Reserved2 = 0x0,
                        Reserved3 = 0x0,
                    },
                    frag4 = new NDR64_MEMPAD_FORMAT
                    {
                        FormatCode = 0x90, /* FC64_STRUCTPADN */
                        Reserved1 = 0x0,
                        MemPad = 0x4,
                        Reserved2 = 0x0
                    },
                    frag5 = new NDR64_SIMPLE_MEMBER_FORMAT
                    {
                        FormatCode = 0x14, /* FC64_POINTER */
                        Reserved1 = 0x0,
                        Reserved2 = 0x0,
                        Reserved3 = 0x0,
                    },
                    frag6 = new NDR64_SIMPLE_MEMBER_FORMAT
                    {
                        FormatCode = 0x93, /* FC64_END */
                        Reserved1 = 0x0,
                        Reserved2 = 0x0,
                        Reserved3 = 0x0,
                    }
                }
            };
            Marshal.StructureToPtr(
                midlFrag143,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag143, 0),
                true);

            var midlFrag144 = new MIDL_FRAG144
            {
                /* *RPC_V2_NOTIFY_OPTIONS_TYPE */
                frag1 = new NDR64_CONF_ARRAY_HEADER_FORMAT
                {
                    FormatCode = 0x41, /* FC64_CONF_ARRAY */
                    Alignment = 0x7,
                    Flags = (NDR64_ARRAY_FLAGS)0x01,
                    Reserved = 0x0,
                    ElementSize = 0x18,
                    ConfDescriptor = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag145, 0)
                },
                frag2 = new MIDL_FRAG144_INNER1
                {
                    frag1 = new NDR64_REPEAT_FORMAT
                    {
                        FormatCode = 0x82, /* FC64_VARIABLE_REPEAT */
                        Flags = NDR64_POINTER_REPEAT_FLAGS.SetCorrMark,
                        Reserved = 0x0,
                        Increment = 0x18,
                        OffsetToArray = 0x0,
                        NumberOfPointers = 0x1
                    },
                    frag2 = new MIDL_FRAG144_INNER2
                    {
                        frag1 = new NDR64_POINTER_INSTANCE_HEADER_FORMAT
                        {
                            Offset = 0x10,
                            Reserved = 0x0
                        },
                        frag2 = new NDR64_POINTER_FORMAT
                        {
                            FormatCode = 0x21, /* FC64_UP */
                            Flags = 0x20,
                            Reserved = 0x0,
                            Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag150, 0)
                        }
                    },
                    frag3 = 0x93 /* FC64_END */
                },
                frag3 = new NDR64_ARRAY_ELEMENT_INFO
                {
                    ElementMemSize = 0x18,
                    Element = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag149, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag144,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag144, 0),
                true);

            var midlFrag145 = new MIDL_FRAG145
            {
                frag1 = 1,
                frag2 = new NDR64_EXPR_VAR
                {
                    ExprType = 0x3, /* FC_EXPR_VAR */
                    VarType = 0x6, /* FC64_UINT32 */
                    Reserved = 0x0,
                    Offset = 0x8
                }
            };
            Marshal.StructureToPtr(
                midlFrag145,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag145, 0),
                true);

            MidlFrag148[0] = 0x4; /* FC64_INT16 */

            var midlFrag149 = new MIDL_FRAG149
            {
                /* RPC_V2_NOTIFY_OPTIONS_TYPE */
                frag1 = new NDR64_STRUCTURE_HEADER_FORMAT
                {
                    FormatCode = 0x31, /* FC64_PSTRUCT */
                    Alignment = 0x7,
                    Flags = NDR64_STRUCTURE_FLAGS.HasPointerInfo,
                    Reserved = 0x0,
                    MemorySize = 0x18
                },
                frag2 = new MIDL_FRAG149_INNER
                {
                    frag1 = new NDR64_NO_REPEAT_FORMAT
                    {
                        FormatCode = 0x80, /* FC64_NO_REPEAT */
                        Flags = 0x0,
                        Reserved1 = 0x0,
                        Reserved2 = 0x0
                    },
                    frag2 = new NDR64_POINTER_INSTANCE_HEADER_FORMAT
                    {
                        Offset = 0x10,
                        Reserved = 0x0
                    },
                    frag3 = new NDR64_POINTER_FORMAT
                    {
                        FormatCode = 0x21, /* FC64_UP */
                        Flags = 0x20,
                        Reserved = 0x0,
                        Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag150, 0)
                    },
                    frag4 = 0x93 /* FC64_END */
                }
            };
            Marshal.StructureToPtr(
                midlFrag149,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag149, 0),
                true);

            var midlFrag150 = new MIDL_FRAG150
            {
                frag1 = new NDR64_CONF_ARRAY_HEADER_FORMAT
                {
                    FormatCode = 0x41, /* FC64_CONF_ARRAY */
                    Alignment = 0x1,
                    Flags = 0x0,
                    Reserved = 0x0,
                    ElementSize = 0x2,
                    ConfDescriptor = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag151, 0)
                },
                frag2 = new NDR64_ARRAY_ELEMENT_INFO
                {
                    ElementMemSize = 0x2,
                    Element = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag148, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag150,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag150, 0),
                true);

            var midlFrag151 = new MIDL_FRAG151
            {
                frag1 = 0x1,
                frag2 = new NDR64_EXPR_VAR
                {
                    ExprType = 0x3, /* FC_EXPR_VAR */
                    VarType = 0x6, /* FC64_UINT32 */
                    Reserved = 0x0,
                    Offset = 0xC
                }
            };
            Marshal.StructureToPtr(
                midlFrag151,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag151, 0),
                true);

            var midlFrag152 = new MIDL_FRAG152
            {
                /* *RPC_V2_NOTIFY_OPTIONS_TYPE */
                frag1 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0x20,
                    Reserved = 0x0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag144, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag152,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag152, 0),
                true);

            MidlFrag153[0] = 0x5; /* FC64_INT32 */

            /*
             * Build Ndr64ProcTable
             */
            Ndr64ProcTable = new IntPtr[66]
            {
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag4, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag73, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag134, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag134, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag134, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag134, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag134, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag134, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag134, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag134, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag134, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag134, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag131, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag134, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag134, 0),
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag135, 0)
            };

            /*
             * Build SyntaxInfo
             */
            var syntaxInfo = new MIDL_SYNTAX_INFO[]
            {
                new MIDL_SYNTAX_INFO
                {
                    TransferSyntax = SyntaxIdentifiers.RpcTransferSyntax_2_0,
                    DispatchTable = IntPtr.Zero,
                    ProcString = Marshal.UnsafeAddrOfPinnedArrayElement(MsRprnConsts.ProcFormatString.Format, 0),
                    FmtStringOffset = Marshal.UnsafeAddrOfPinnedArrayElement(MsRprnConsts.FormatStringOffsetTable, 0),
                    TypeString = Marshal.UnsafeAddrOfPinnedArrayElement(MsRprnConsts.TypeFormatString.Format, 0),
                    aUserMarshalQuadruple = IntPtr.Zero,
                    pMethodProperties = IntPtr.Zero,
                    pReserved2 = UIntPtr.Zero
                },
                new MIDL_SYNTAX_INFO
                {
                    TransferSyntax = SyntaxIdentifiers.RpcTransferSyntax64_2_0,
                    DispatchTable = IntPtr.Zero,
                    ProcString = IntPtr.Zero,
                    FmtStringOffset = Marshal.UnsafeAddrOfPinnedArrayElement(Ndr64ProcTable, 0),
                    TypeString = IntPtr.Zero,
                    aUserMarshalQuadruple = IntPtr.Zero,
                    pMethodProperties = IntPtr.Zero,
                    pReserved2 = UIntPtr.Zero
                }
            };

            for (var idx = 0; idx < syntaxInfo.Length; idx++)
            {
                IntPtr pEntry;

                if (Environment.Is64BitProcess)
                    pEntry = new IntPtr(pSyntaxInfo.ToInt64() + (idx * Marshal.SizeOf(typeof(MIDL_SYNTAX_INFO))));
                else
                    pEntry = new IntPtr(pSyntaxInfo.ToInt32() + (idx * Marshal.SizeOf(typeof(MIDL_SYNTAX_INFO))));

                Marshal.StructureToPtr(syntaxInfo[idx], pEntry, true);
            }

            /*
             * Build _RpcTransferSyntax_2_0
             */
            Marshal.StructureToPtr(SyntaxIdentifiers.RpcTransferSyntax_2_0, pRpcTransferSyntax, false);

            /*
             * Build __RpcProtseqEndpoint
             */
            pSequenceName = Marshal.StringToHGlobalAnsi("ncacn_np");
            pEndpointPath = Marshal.StringToHGlobalAnsi(@"\pipe\spoolss");

            var rpcRequestEndpoint = new RPC_PROTSEQ_ENDPOINT
            {
                RpcProtocolSequence = pSequenceName,
                Endpoint = pEndpointPath
            };
            Marshal.StructureToPtr(rpcRequestEndpoint, pRpcProtseqEndpoint, true);

            /*
             * Build winspool___RpcClientInterface
             */
            var rpcClientInterface = new RPC_CLIENT_INTERFACE
            {
                Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE)),
                InterfaceId = SyntaxIdentifiers.RpcUuidSyntax_1_0,
                TransferSyntax = SyntaxIdentifiers.RpcTransferSyntax_2_0,
                DispatchTable = IntPtr.Zero,
                RpcProtseqEndpointCount = 1u,
                RpcProtseqEndpoint = pRpcProtseqEndpoint,
                Reserved = UIntPtr.Zero,
                InterpreterInfo = pProxyInfo,
                Flags = 0x02000000u
            };
            Marshal.StructureToPtr(rpcClientInterface, pRpcClientInterface, true);

            /*
             * Build winspool_StubDesc
             */
            var stubDesc = new MIDL_STUB_DESC(
                pRpcClientInterface,
                Marshal.GetFunctionPointerForDelegate((MIDL_USER_ALLOCATE)RpcRoutines.Malloc),
                Marshal.GetFunctionPointerForDelegate((MIDL_USER_FREE)RpcRoutines.Free),
                pAutoHandle,
                Marshal.UnsafeAddrOfPinnedArrayElement(MsRprnConsts.TypeFormatString.Format, 0),
                pBindingRoutinePair,
                pProxyInfo);
            Marshal.StructureToPtr(stubDesc, pStubDesc, true);

            /*
             * Build winspool_ProxyInfo
             */
            var proxyInfo = new MIDL_STUBLESS_PROXY_INFO
            {
                pStubDesc = pStubDesc,
                ProcFormatString = Marshal.UnsafeAddrOfPinnedArrayElement(MsRprnConsts.ProcFormatString.Format, 0),
                FormatStringOffset = Marshal.UnsafeAddrOfPinnedArrayElement(MsRprnConsts.FormatStringOffsetTable, 0),
                pTransferSyntax = pRpcTransferSyntax,
                nCount = new UIntPtr(2u),
                pSyntaxInfo = pSyntaxInfo
            };
            Marshal.StructureToPtr(proxyInfo, pProxyInfo, true);
        }


        public void Dispose()
        {
            Marshal.FreeHGlobal(pProxyInfo);
            Marshal.FreeHGlobal(pStubDesc);
            Marshal.FreeHGlobal(pBindingRoutinePair);
            Marshal.FreeHGlobal(pRpcClientInterface);
            Marshal.FreeHGlobal(pRpcTransferSyntax);
            Marshal.FreeHGlobal(pRpcProtseqEndpoint);
            Marshal.FreeHGlobal(pAutoHandle);
            Marshal.FreeHGlobal(pSyntaxInfo);
            Marshal.FreeHGlobal(pSequenceName);
            Marshal.FreeHGlobal(pEndpointPath);
        }

        /*
         * public functions
         */
        public RPC_STATUS RpcClosePrinter(ref IntPtr pPrinterHandle)
        {
            RPC_STATUS rpcStatus;

            try
            {
                IntPtr returnedCode = NativeMethods.NdrClientCall3(
                    pProxyInfo,
                    29u,
                    IntPtr.Zero,
                    ref pPrinterHandle);

                if (Environment.Is64BitProcess)
                    rpcStatus = (RPC_STATUS)(returnedCode.ToInt64() & 0x00000000_FFFFFFFFL);
                else
                    rpcStatus = returnedCode.ToInt32();
            }
            catch (SEHException)
            {
                rpcStatus = Marshal.GetExceptionCode();
            }

            return rpcStatus;
        }


        public RPC_STATUS RpcOpenPrinter(
            string printerName,
            out IntPtr hPrinter,
            string dataType,
            ref DEVMODE_CONTAINER devmodeContainer,
            int accessRequired)
        {
            RPC_STATUS rpcStatus;
            
            try
            {
                IntPtr returnedCode = NativeMethods.NdrClientCall3(
                    pProxyInfo,
                    1u,
                    IntPtr.Zero,
                    printerName,
                    out hPrinter,
                    dataType,
                    ref devmodeContainer,
                    accessRequired);

                if (Environment.Is64BitProcess)
                    rpcStatus = (RPC_STATUS)(returnedCode.ToInt64() & 0x00000000_FFFFFFFFL);
                else
                    rpcStatus = returnedCode.ToInt32();
            }
            catch (SEHException)
            {
                rpcStatus = Marshal.GetExceptionCode();
                hPrinter = IntPtr.Zero;
            }

            return rpcStatus;
        }


        public RPC_STATUS RpcRemoteFindFirstPrinterChangeNotificationEx(
            IntPtr hPrinter,
            PRINTER_CHANGE_FLAGS fdwFlags,
            int fdwOptions,
            string pszLocalMachine, // Unicode
            int dwPrinterLocal,
            IntPtr /* in RPC_V2_NOTIFY_OPTIONS */ pOptions)
        {
            RPC_STATUS rpcStatus;

            try
            {
                IntPtr returnedCode = NativeMethods.NdrClientCall3(
                    pProxyInfo,
                    65u,
                    IntPtr.Zero,
                    hPrinter,
                    fdwFlags,
                    fdwOptions,
                    pszLocalMachine,
                    dwPrinterLocal,
                    pOptions);

                if (Environment.Is64BitProcess)
                    rpcStatus = (RPC_STATUS)(returnedCode.ToInt64() & 0x00000000_FFFFFFFFL);
                else
                    rpcStatus = returnedCode.ToInt32();
            }
            catch (SEHException)
            {
                rpcStatus = Marshal.GetExceptionCode();
            }

            return rpcStatus;
        }
    }
}
