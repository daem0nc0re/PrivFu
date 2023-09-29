using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using RpcLibrary.Interop;

namespace RpcLibrary
{
    internal class SyncController : IDisposable
    {
        public readonly IntPtr SyncController_v1_0_c_ifspec = IntPtr.Zero;

        private readonly byte[] MidlFrag28 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG28))];
        private readonly byte[] MidlFrag30 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG30))];
        private readonly byte[] MidlFrag40 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG40))];
        private readonly byte[] MidlFrag41 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG41))];
        private readonly RPC_CLIENT_INTERFACE RpcClientInterface = new RPC_CLIENT_INTERFACE
        {
            Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE)),
            InterfaceId = SyntaxId.SyncControllerSyntax_1_0,
            TransferSyntax = SyntaxId.RpcTransferSyntax_2_0,
            DispatchTable = IntPtr.Zero,
            RpcProtseqEndpointCount = 0u,
            RpcProtseqEndpoint = IntPtr.Zero,
            Reserved = UIntPtr.Zero,
            InterpreterInfo = IntPtr.Zero, // Must be patched with pointer to ProxyInfo.
            Flags = 0x02000000u
        };
        private readonly IntPtr[] Ndr64ProcTable = new IntPtr[SyncControllerConsts.FORMAT_TABLE_LENGTH];

        public SyncController()
        {
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
        }

        public void Dispose()
        {
        }
    }
}
