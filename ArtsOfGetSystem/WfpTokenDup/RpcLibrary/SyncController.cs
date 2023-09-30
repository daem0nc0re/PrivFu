using System;
using System.Runtime.InteropServices;
using RpcLibrary.Interop;

namespace RpcLibrary
{
    using RPC_STATUS = Int32;

    internal class SyncController : IDisposable
    {
        public readonly IntPtr SyncController_v1_0_c_ifspec = IntPtr.Zero;

        private readonly IntPtr pProxyInfo = IntPtr.Zero;
        private readonly IntPtr pStubDesc = IntPtr.Zero;
        private readonly IntPtr pTransferSyntax = IntPtr.Zero;
        private readonly IntPtr pClientInterface = IntPtr.Zero;
        private readonly IntPtr pSyntaxInfo = IntPtr.Zero;
        private readonly IntPtr pAutoBindHandle = IntPtr.Zero;
        private readonly byte[] MidlFrag28 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG28))];
        private readonly byte[] MidlFrag30 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG30))];
        private readonly byte[] MidlFrag40 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG40))];
        private readonly byte[] MidlFrag41 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG41))];
        private readonly IntPtr[] Ndr64ProcTable = new IntPtr[SyncControllerConsts.FORMAT_TABLE_LENGTH];

        /*
         * Constructor and Destructor definition
         */
        public SyncController()
        {
            /*
             * Build Ndr64ProcTable
             */
            var midlFrag28 = new MIDL_FRAG28
            {
                /* AccountsMgmtRpcDiscoverExchangeServerAuthType procedure */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x010C0040u, /* IsIntrepreted, ClientMustSize, HasReturn, HasExtensions */
                    StackSize = 0x20u,
                    ConstantClientBufferSize = 0x0u,
                    ConstantServerBufferSize = 0x28u,
                    RpcFlags = 0x0,
                    FloatDoubleMask = 0x0,
                    NumberOfParams = 0x3,
                    ExtensionSize = 0x8
                },
                /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
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
                /* ServerAddress parameter */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag30, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0x0,
                    StackOffset = 0x8
                },
                /* IntOut parameter */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag41, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x8150,
                    Reserved = 0x0,
                    StackOffset = 0x10
                },
                /* int parameter */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag41, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0x0,
                    StackOffset = 0x18
                }
            };
            Marshal.StructureToPtr(midlFrag28, Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag28, 0), true);

            var midlFrag30 = new MIDL_FRAG30
            {
                Header = new NDR64_STRING_HEADER_FORMAT
                {
                    FormatCode = 0x64, /* FC64_CONF_WCHAR_STRING */
                    Flags = 0x0,
                    ElementSize = 0x2
                }
            };
            Marshal.StructureToPtr(midlFrag30, Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag30, 0), true);

            var midlFrag40 = new MIDL_FRAG40
            {
                /* AccountsMgmtRpcMayIgnoreInvalidServerCertificate procedure */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x1080040u, /* IsIntrepreted, HasReturn, HasExtensions */
                    StackSize = 0x10,
                    ConstantClientBufferSize = 0x0,
                    ConstantServerBufferSize = 0x8,
                    RpcFlags = 0x0,
                    FloatDoubleMask = 0x0,
                    NumberOfParams = 0x1,
                    ExtensionSize = 0x8
                },
                /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
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
                /* int parameter */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag41, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0x0,
                    StackOffset = 0x8
                }
            };
            Marshal.StructureToPtr(midlFrag40, Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag40, 0), true);

            MidlFrag41[0] = 0x5; /* FC64_INT32 */

            for (var idx = 0; idx < Ndr64ProcTable.Length; idx++)
                Ndr64ProcTable[idx] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag40, 0);

            Ndr64ProcTable[13] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag28, 0);

            /*
             * Allocate Buffers
             */
            pProxyInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(MIDL_STUBLESS_PROXY_INFO)));
            pStubDesc = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(MIDL_STUB_DESC)));
            pTransferSyntax = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(RPC_SYNTAX_IDENTIFIER)));
            pClientInterface = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE)));
            pSyntaxInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(MIDL_SYNTAX_INFO)) * 2);
            pAutoBindHandle = Marshal.AllocHGlobal(IntPtr.Size);
            SyncController_v1_0_c_ifspec = pClientInterface;
            Marshal.WriteIntPtr(pAutoBindHandle, IntPtr.Zero);

            /*
             * Build ProxyInfo
             */
            var proxyInfo = new MIDL_STUBLESS_PROXY_INFO
            {
                pStubDesc = pStubDesc,
                ProcFormatString = Marshal.UnsafeAddrOfPinnedArrayElement(SyncControllerConsts.ProcFormatString.Format, 0),
                FormatStringOffset = Marshal.UnsafeAddrOfPinnedArrayElement(SyncControllerConsts.FormatStringOffsetTable, 0),
                pTransferSyntax = pTransferSyntax,
                nCount = new UIntPtr(2u),
                pSyntaxInfo = pSyntaxInfo
            };
            Marshal.StructureToPtr(proxyInfo, pProxyInfo, true);

            /*
             * Build StubDesc
             */
            var stubDesc = new MIDL_STUB_DESC
            {
                RpcInterfaceInformation = pClientInterface,
                pfnAllocate = Marshal.GetFunctionPointerForDelegate((MIDL_USER_ALLOCATE)RpcRoutines.Malloc),
                pfnFree = Marshal.GetFunctionPointerForDelegate((MIDL_USER_FREE)RpcRoutines.Free),
                handleInfo = new IMPLICIT_HANDLE_INFO { pAutoHandle = pAutoBindHandle },
                apfnNdrRundownRoutines = IntPtr.Zero,
                aGenericBindingRoutinePairs = IntPtr.Zero,
                apfnExprEval = IntPtr.Zero,
                aXmitQuintuple = IntPtr.Zero,
                pFormatTypes = Marshal.UnsafeAddrOfPinnedArrayElement(SyncControllerConsts.TypeFormatString.Format, 0),
                fCheckBounds = 1,
                Version = 0x00060001u,
                pMallocFreeStruct = IntPtr.Zero,
                MIDLVersion = 0x08010274,
                CommFaultOffsets = IntPtr.Zero,
                aUserMarshalQuadruple = IntPtr.Zero,
                NotifyRoutineTable = IntPtr.Zero,
                mFlags = new UIntPtr(0x02000001u),
                CsRoutineTables = IntPtr.Zero,
                ProxyServerInfo = pProxyInfo,
                pExprInfo = IntPtr.Zero
            };
            Marshal.StructureToPtr(stubDesc, pStubDesc, true);

            /*
             * Build RpcTransferSyntax
             */
            Marshal.StructureToPtr(SyntaxIdentifiers.RpcTransferSyntax_2_0, pTransferSyntax, false);

            /*
             * Build RpcClientInterface
             */
            var rpcClientInterface = new RPC_CLIENT_INTERFACE
            {
                Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE)),
                InterfaceId = SyntaxIdentifiers.SyncControllerSyntax_1_0,
                TransferSyntax = SyntaxIdentifiers.RpcTransferSyntax_2_0,
                DispatchTable = IntPtr.Zero,
                RpcProtseqEndpointCount = 0u,
                RpcProtseqEndpoint = IntPtr.Zero,
                Reserved = UIntPtr.Zero,
                InterpreterInfo = pProxyInfo,
                Flags = 0x02000000u
            };
            Marshal.StructureToPtr(rpcClientInterface, pClientInterface, true);

            /*
             * Build SyntaxInfo
             */
            var syntaxInfo = new MIDL_SYNTAX_INFO
            {
                TransferSyntax = SyntaxIdentifiers.RpcTransferSyntax_2_0,
                DispatchTable = IntPtr.Zero,
                ProcString = Marshal.UnsafeAddrOfPinnedArrayElement(SyncControllerConsts.ProcFormatString.Format, 0),
                FmtStringOffset = Marshal.UnsafeAddrOfPinnedArrayElement(SyncControllerConsts.FormatStringOffsetTable, 0),
                TypeString = Marshal.UnsafeAddrOfPinnedArrayElement(SyncControllerConsts.TypeFormatString.Format, 0),
                aUserMarshalQuadruple = IntPtr.Zero,
                pMethodProperties = IntPtr.Zero,
                pReserved2 = UIntPtr.Zero
            };

            Marshal.StructureToPtr(syntaxInfo, pSyntaxInfo, false);

            IntPtr pSyntaxInfo1;
            syntaxInfo.TransferSyntax = SyntaxIdentifiers.RpcTransferSyntax64_2_0;
            syntaxInfo.ProcString = IntPtr.Zero;
            syntaxInfo.FmtStringOffset = Marshal.UnsafeAddrOfPinnedArrayElement(Ndr64ProcTable, 0);
            syntaxInfo.TypeString = IntPtr.Zero;

            if (Environment.Is64BitProcess)
                pSyntaxInfo1 = new IntPtr(pSyntaxInfo.ToInt64() + Marshal.SizeOf(syntaxInfo));
            else
                pSyntaxInfo1 = new IntPtr(pSyntaxInfo.ToInt32() + Marshal.SizeOf(syntaxInfo));

            Marshal.StructureToPtr(syntaxInfo, pSyntaxInfo1, true);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(pProxyInfo);
            Marshal.FreeHGlobal(pStubDesc);
            Marshal.FreeHGlobal(pTransferSyntax);
            Marshal.FreeHGlobal(pClientInterface);
            Marshal.FreeHGlobal(pSyntaxInfo);
            Marshal.FreeHGlobal(pAutoBindHandle);
        }

        /*
         * RPC Methods
         */
        public RPC_STATUS AccountsMgmtRpcDiscoverExchangeServerAuthType(
            IntPtr IDL_handle,
            string ServerAddress,
            out int IntOut)
        {
            RPC_STATUS rpcStatus;
            IntOut = 0;

            try
            {
                IntPtr returnedCode = NativeMethods.NdrClientCall3(
                    pProxyInfo,
                    13u,
                    IntPtr.Zero,
                    IDL_handle,
                    ServerAddress,
                    out IntOut);

                if (Environment.Is64BitProcess)
                    rpcStatus = (int)(returnedCode.ToInt64() & 0x00000000_FFFFFFFFL);
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
