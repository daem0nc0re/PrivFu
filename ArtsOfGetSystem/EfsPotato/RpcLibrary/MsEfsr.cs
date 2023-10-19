using System;
using System.Runtime.InteropServices;
using RpcLibrary.Interop;

namespace RpcLibrary
{
    using RPC_STATUS = Int32;

    internal class MsEfsr : IDisposable
    {
        private static readonly byte[] MidlFrag2 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG2_EFSR))];
        private static readonly byte[] MidlFrag4 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG4_EFSR))];
        private static readonly byte[] MidlFrag9 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG9_EFSR))];
        private static readonly byte[] MidlFrag15 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG15_EFSR))];
        private static readonly byte[] MidlFrag16 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG16_EFSR))];
        private static readonly byte[] MidlFrag18 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG18_EFSR))];
        private static readonly byte[] MidlFrag21 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG21_EFSR))];
        private static readonly byte[] MidlFrag23 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG23_EFSR))];
        private static readonly byte[] MidlFrag24 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG24_EFSR))];
        private static readonly byte[] MidlFrag28 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG28_EFSR))];
        private static readonly byte[] MidlFrag38 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG38_EFSR))];
        private static readonly byte[] MidlFrag39 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG39_EFSR))];
        private static readonly byte[] MidlFrag41 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG41_EFSR))];
        private static readonly byte[] MidlFrag42 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG42_EFSR))];
        private static readonly byte[] MidlFrag43 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG43_EFSR))];
        private static readonly byte[] MidlFrag44 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG44_EFSR))];
        private static readonly byte[] MidlFrag46 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG46_EFSR))];
        private static readonly byte[] MidlFrag47 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG47_EFSR))];
        private static readonly byte[] MidlFrag48 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG48_EFSR))];
        private static readonly byte[] MidlFrag50 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG50_EFSR))];
        private static readonly byte[] MidlFrag52 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG52_EFSR))];
        private static readonly byte[] MidlFrag53 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG53_EFSR))];
        private static readonly byte[] MidlFrag54 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG54_EFSR))];
        private static readonly byte[] MidlFrag56 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG56_EFSR))];
        private static readonly byte[] MidlFrag59 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG59_EFSR))];
        private static readonly byte[] MidlFrag60 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG60_EFSR))];
        private static readonly byte[] MidlFrag62 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG62_EFSR))];
        private static readonly byte[] MidlFrag67 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG67_EFSR))];
        private static readonly byte[] MidlFrag71 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG71_EFSR))];
        private static readonly byte[] MidlFrag72 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG72_EFSR))];
        private static readonly byte[] MidlFrag73 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG73_EFSR))];
        private static readonly byte[] MidlFrag74 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG74_EFSR))];
        private static readonly byte[] MidlFrag75 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG75_EFSR))];
        private static readonly byte[] MidlFrag76 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG76_EFSR))];
        private static readonly byte[] MidlFrag77 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG77_EFSR))];
        private static readonly byte[] MidlFrag79 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG79_EFSR))];
        private static readonly byte[] MidlFrag80 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG80_EFSR))];
        private static readonly byte[] MidlFrag81 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG81_EFSR))];
        private static readonly byte[] MidlFrag92 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG92_EFSR))];
        private static readonly byte[] MidlFrag93 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG93_EFSR))];
        private static readonly byte[] MidlFrag94 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG94_EFSR))];
        private static readonly byte[] MidlFrag95 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG95_EFSR))];
        private static readonly byte[] MidlFrag96 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG96_EFSR))];
        private static readonly byte[] MidlFrag99 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG99_EFSR))];
        private static readonly byte[] MidlFrag106 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG106_EFSR))];
        private static readonly byte[] MidlFrag117 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG117_EFSR))];
        private static readonly byte[] MidlFrag124 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG124_EFSR))];
        private static readonly byte[] MidlFrag134 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG134_EFSR))];
        private static readonly byte[] MidlFrag137 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG137_EFSR))];
        private static readonly byte[] MidlFrag140 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG140_EFSR))];
        private static readonly byte[] MidlFrag143 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG143_EFSR))];
        private static readonly byte[] MidlFrag145 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG145_EFSR))];
        private static readonly byte[] MidlFrag146 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG146_EFSR))];
        private static readonly byte[] MidlFrag147 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG147_EFSR))];
        private static readonly byte[] MidlFrag149 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG149_EFSR))];
        private static readonly byte[] MidlFrag151 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG151_EFSR))];
        private static readonly byte[] MidlFrag154 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG154_EFSR))];
        private static readonly byte[] MidlFrag158 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG158_EFSR))];
        private static readonly byte[] MidlFrag161 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG161_EFSR))];
        private static readonly byte[] MidlFrag162 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG162_EFSR))];
        private static readonly byte[] MidlFrag163 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG163_EFSR))];
        private static readonly byte[] MidlFrag164 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG164_EFSR))];
        private static readonly byte[] MidlFrag165 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG165_EFSR))];
        private static readonly byte[] MidlFrag166 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG166_EFSR))];
        private static readonly byte[] MidlFrag167 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG167_EFSR))];
        private static readonly byte[] MidlFrag168 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG168_EFSR))];
        private static readonly byte[] MidlFrag169 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG169_EFSR))];
        private static readonly byte[] MidlFrag170 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG170_EFSR))];
        private static readonly byte[] MidlFrag171 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG171_EFSR))];
        private static readonly byte[] MidlFrag172 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG172_EFSR))];
        private static readonly byte[] MidlFrag194 = new byte[Marshal.SizeOf(typeof(MIDL_FRAG194_EFSR))];

        private readonly IntPtr pProxyInfo = IntPtr.Zero;
        private readonly IntPtr pStubDesc = IntPtr.Zero;
        private readonly IntPtr pRpcClientInterface = IntPtr.Zero;
        private readonly IntPtr pAutoBindHandle = IntPtr.Zero;
        private readonly IntPtr pRpcTransferSyntax = IntPtr.Zero;
        private readonly IntPtr pSyntaxInfo = IntPtr.Zero;
        private readonly string EndpointUuidString = null;
        private readonly string EndpointPipePath = null;

        private static readonly IntPtr[] Ndr64ProcTable = new IntPtr[MsEfsrConsts.FORMAT_TABLE_LENGTH];

        public MsEfsr(string pipeName)
        {
            /*
             * Set Endpoint UUID
             * 
             * UUID reference:
             * * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/1baaad2f-7a84-4238-b113-f32827a39cd2
             * * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/ab3c0be4-5b55-4a08-b198-f17170100be6
             */
            if (string.Compare(pipeName, "efsrpc", StringComparison.OrdinalIgnoreCase) == 0)
            {
                EndpointUuidString = "DF1941C5-FE89-4E79-BF10-463657ACF44D";
                EndpointPipePath = @"\pipe\efsrpc";
            }
            else if (string.Compare(pipeName, "lsarpc", StringComparison.OrdinalIgnoreCase) == 0)
            {
                EndpointUuidString = "C681D488-D850-11D0-8C52-00C04FD90F7E";
                EndpointPipePath = @"\pipe\lsarpc";
            }
            else if (string.Compare(pipeName, "lsass", StringComparison.OrdinalIgnoreCase) == 0)
            {
                EndpointUuidString = "C681D488-D850-11D0-8C52-00C04FD90F7E";
                EndpointPipePath = @"\pipe\lsass";
            }
            else if (string.Compare(pipeName, "netlogon", StringComparison.OrdinalIgnoreCase) == 0)
            {
                EndpointUuidString = "C681D488-D850-11D0-8C52-00C04FD90F7E";
                EndpointPipePath = @"\pipe\netlogon";
            }
            else if (string.Compare(pipeName, "samr", StringComparison.OrdinalIgnoreCase) == 0)
            {
                EndpointUuidString = "C681D488-D850-11D0-8C52-00C04FD90F7E";
                EndpointPipePath = @"\pipe\samr";
            }
            else
            {
                throw new NotImplementedException("Invalid endpoint pipe name");
            }

            /*
             * Allocate required buffers
             */
            int nInfoLength = Marshal.SizeOf(typeof(MIDL_STUBLESS_PROXY_INFO));
            pProxyInfo = Marshal.AllocHGlobal(nInfoLength);

            nInfoLength = Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
            pRpcClientInterface = Marshal.AllocHGlobal(nInfoLength);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_STUB_DESC));
            pStubDesc = Marshal.AllocHGlobal(nInfoLength);

            pAutoBindHandle = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pAutoBindHandle, IntPtr.Zero);

            nInfoLength = Marshal.SizeOf(typeof(RPC_SYNTAX_IDENTIFIER));
            pRpcTransferSyntax = Marshal.AllocHGlobal(nInfoLength);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_SYNTAX_INFO)) * 2;
            pSyntaxInfo = Marshal.AllocHGlobal(nInfoLength);

            /*
             * Build SyntaxInfo
             */
            var midlFrag2 = new MIDL_FRAG2_EFSR
            {
                /* procedure EfsRpcOpenFileRaw */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x010C0040u,
                    StackSize = 0x28u,
                    ConstantClientBufferSize = 0x8u,
                    ConstantServerBufferSize = 0x44u,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x4,
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
                    NotifyIndex = 0,
                },
                /* parameter hContext */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag4, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x0110,
                    Reserved = 0,
                    StackOffset = 0x8
                },
                /* parameter FileName */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x10
                },
                /* parameter Flags */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00C8,
                    Reserved = 0,
                    StackOffset = 0x18
                },
                /* parameter long */
                frag6 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x20
                }
            };
            Marshal.StructureToPtr(
                midlFrag2,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag2, 0),
                true);

            var midlFrag4 = new MIDL_FRAG4_EFSR
            {
                FormatCode = 0x70, /* FC64_BIND_CONTEXT */
                ContextFlags = 0xA0,
                RundownRoutineIndex = 0,
                Ordinal = 0
            };
            Marshal.StructureToPtr(
                midlFrag4,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag4, 0),
                true);

            var midlFrag9 = new MIDL_FRAG9_EFSR
            {
                /* procedure EfsRpcReadFileRaw */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x01084040,
                    StackSize = 0x18u,
                    ConstantClientBufferSize = 0x24u,
                    ConstantServerBufferSize = 0x8u,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x3,
                    ExtensionSize = 0x8
                },
                frag2 = new NDR64_BIND_AND_NOTIFY_EXTENSION
                {
                    Binding = new NDR64_BIND_CONTEXT
                    {
                        HandleType = 0x70, /* FC64_BIND_CONTEXT */
                        Flags = 0x40,
                        StackOffset = 0,
                        RoutineIndex = 0,
                        Ordinal = 0
                    },
                    NotifyIndex = 0,
                },
                /* parameter hContext */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag16, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x0008,
                    Reserved = 0,
                    StackOffset = 0x0
                },
                /* EfsOutPipe */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag18, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x8114,
                    Reserved = 0,
                    StackOffset = 0x8
                },
                /* parameter long */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x10
                }
            };
            Marshal.StructureToPtr(
                midlFrag9,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag9, 0),
                true);

            var midlFrag15 = new MIDL_FRAG15_EFSR
            {
                /* procedure EfsRpcWriteFileRaw */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x01084040,
                    StackSize = 0x18u,
                    ConstantClientBufferSize = 0x24u,
                    ConstantServerBufferSize = 0x8u,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x3,
                    ExtensionSize = 0x8
                },
                frag2 = new NDR64_BIND_AND_NOTIFY_EXTENSION
                {
                    Binding = new NDR64_BIND_CONTEXT
                    {
                        HandleType = 0x70, /* FC64_BIND_CONTEXT */
                        Flags = 0x40,
                        StackOffset = 0,
                        RoutineIndex = 0,
                        Ordinal = 0
                    },
                    NotifyIndex = 0,
                },
                /* parameter hContext */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag16, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x0008,
                    Reserved = 0,
                    StackOffset = 0x0
                },
                /* parameter EfsInPipe */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag18, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010C,
                    Reserved = 0,
                    StackOffset = 0x8
                },
                /* parameter long */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x10
                }
            };
            Marshal.StructureToPtr(
                midlFrag15,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag15, 0),
                true);

            var midlFrag16 = new MIDL_FRAG16_EFSR
            {
                FormatCode = 0x70, /* FC64_BIND_CONTEXT */
                ContextFlags = 0x41,
                RundownRoutineIndex = 0,
                Ordinal = 0
            };
            Marshal.StructureToPtr(
                midlFrag16,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag16, 0),
                true);

            var midlFrag18 = new MIDL_FRAG18_EFSR
            {
                FormatCode = 0xA3, /* FC64_PIPE */
                Flags = 0x40,
                Alignment = 0,
                Reserved = 0,
                Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag95, 0),
                MemorySize = 1u,
                BufferSize = 1u
            };
            Marshal.StructureToPtr(
                midlFrag18,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag18, 0),
                true);

            var midlFrag21 = new MIDL_FRAG21_EFSR
            {
                /* procedure EfsRpcCloseRaw */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x01000040,
                    StackSize = 0x8u,
                    ConstantClientBufferSize = 0x3Cu,
                    ConstantServerBufferSize = 0x3Cu,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x1,
                    ExtensionSize = 0x8
                },
                frag2 = new NDR64_BIND_AND_NOTIFY_EXTENSION
                {
                    Binding = new NDR64_BIND_CONTEXT
                    {
                        HandleType = 0x70, /* FC64_BIND_CONTEXT */
                        Flags = 0xE0,
                        StackOffset = 0,
                        RoutineIndex = 0,
                        Ordinal = 0
                    },
                    NotifyIndex = 0,
                },
                /* parameter hContext */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag23, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x0118,
                    Reserved = 0,
                    StackOffset = 0x0
                }
            };
            Marshal.StructureToPtr(
                midlFrag21,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag21, 0),
                true);

            var midlFrag23 = new MIDL_FRAG23_EFSR
            {
                FormatCode = 0x70, /* FC64_BIND_CONTEXT */
                ContextFlags = 0xE1,
                RundownRoutineIndex = 0,
                Ordinal = 0
            };
            Marshal.StructureToPtr(
                midlFrag23,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag23, 0),
                true);

            var midlFrag24 = new MIDL_FRAG24_EFSR
            {
                /* procedure EfsRpcEncryptFileSrv */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x010c0040,
                    StackSize = 0x18u,
                    ConstantClientBufferSize = 0,
                    ConstantServerBufferSize = 0x8u,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x2,
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
                    NotifyIndex = 0,
                },
                /* parameter FileName */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x8
                },
                /* parameter long */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x10
                }
            };
            Marshal.StructureToPtr(
                midlFrag24,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag24, 0),
                true);

            var midlFrag28 = new MIDL_FRAG28_EFSR
            {
                /* procedure EfsRpcDecryptFileSrv */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x010C0040,
                    StackSize = 0x20u,
                    ConstantClientBufferSize = 0x8u,
                    ConstantServerBufferSize = 0x8u,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x3,
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
                    NotifyIndex = 0,
                },
                /* parameter FileName */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x8
                },
                /* parameter OpenFlag */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00C8,
                    Reserved = 0,
                    StackOffset = 0x10
                },
                /* parameter long */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x18
                }
            };
            Marshal.StructureToPtr(
                midlFrag28,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag28, 0),
                true);

            var midlFrag38 = new MIDL_FRAG38_EFSR
            {
                /* ENCRYPTION_CERTIFICATE_HASH_LIST */
                frag1 = new NDR64_BOGUS_STRUCTURE_HEADER_FORMAT
                {
                    FormatCode = 0x35, /* FC64_FORCED_BOGUS_STRUCT */
                    Alignment = 0x7,
                    Flags = (NDR64_STRUCTURE_FLAGS)0x3,
                    Reserved = 0,
                    MemorySize = 0x10u,
                    OriginalMemberLayout = IntPtr.Zero,
                    OriginalPointerLayout = IntPtr.Zero,
                    PointerLayout = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag54, 0)
                },
                frag2_1 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x5, /* FC64_INT32 */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_2 = new NDR64_MEMPAD_FORMAT
                {
                    FormatCode = 0x90, /* FC64_STRUCTPADN */
                    Reserved1 = 0,
                    MemPad = 0x4,
                    Reserved2 = 0
                },
                frag2_3 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x14, /* FC64_POINTER */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_4 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x93, /* FC64_END */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                }
            };
            Marshal.StructureToPtr(
                midlFrag38,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag38, 0),
                true);

            var midlFrag39 = new MIDL_FRAG39_EFSR
            {
                /* **ENCRYPTION_CERTIFICATE_HASH */
                frag1 = new NDR64_CONF_ARRAY_HEADER_FORMAT
                {
                    FormatCode = 0x41, /* FC64_CONF_ARRAY */
                    Alignment = 0x7,
                    Flags = (NDR64_ARRAY_FLAGS)0x1,
                    Reserved = 0,
                    ElementSize = 0x8,
                    ConfDescriptor = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag73, 0)
                },
                frag2_1 = new NDR64_REPEAT_FORMAT
                {
                    FormatCode = 0x82, /* FC64_VARIABLE_REPEAT */
                    Flags = NDR64_POINTER_REPEAT_FLAGS.None,
                    Reserved = 0,
                    Increment = 0x8u,
                    OffsetToArray = 0,
                    NumberOfPointers = 0x1u
                },
                frag2_2_1 = new NDR64_POINTER_INSTANCE_HEADER_FORMAT
                {
                    Offset = 0,
                    Reserved = 0
                },
                frag2_2_2 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag41, 0)
                },
                frag2_3 = 0x93, /* FC64_END */
                frag3 = new NDR64_ARRAY_ELEMENT_INFO
                {
                    ElementMemSize = 0x8,
                    Element = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag53, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag39,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag39, 0),
                true);

            var midlFrag41 = new MIDL_FRAG41_EFSR
            {
                /* ENCRYPTION_CERTIFICATE_HASH */
                frag1 = new NDR64_BOGUS_STRUCTURE_HEADER_FORMAT
                {
                    FormatCode = 0x35, /* FC64_FORCED_BOGUS_STRUCT */
                    Alignment = 0x7,
                    Flags = (NDR64_STRUCTURE_FLAGS)0x3, /* ENCRYPTION_CERTIFICATE_HASH */
                    Reserved = 0,
                    MemorySize = 0x20u,
                    OriginalMemberLayout = IntPtr.Zero,
                    OriginalPointerLayout = IntPtr.Zero,
                    PointerLayout = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag52, 0)
                },
                frag2_1 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x5, /* FC64_INT32 */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_2 = new NDR64_MEMPAD_FORMAT
                {
                    FormatCode = 0x90, /* FC64_STRUCTPADN */
                    Reserved1 = 0,
                    MemPad = 0x4,
                    Reserved2 = 0
                },
                frag2_3 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x14, /* FC64_POINTER */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_4 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x14, /* FC64_POINTER */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_5 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x14, /* FC64_POINTER */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_6 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x93, /* FC64_END */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                }
            };
            Marshal.StructureToPtr(
                midlFrag41,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag41, 0),
                true);

            var midlFrag42 = new MIDL_FRAG42_EFSR
            {
                /* RPC_SID */
                frag1 = new NDR64_CONF_STRUCTURE_HEADER_FORMAT
                {
                    FormatCode = 0x32, /* FC64_CONF_STRUCT */
                    Alignment = 0x3,
                    Flags = NDR64_STRUCTURE_FLAGS.HasConfArray,
                    Reserved = 0,
                    ElementSize = 0x8,
                    ConfDescriptor = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag43, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag42,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag42, 0),
                true);

            var midlFrag43 = new MIDL_FRAG43_EFSR
            {
                frag1 = new NDR64_CONF_ARRAY_HEADER_FORMAT
                {
                    FormatCode = 0x41, /* FC64_CONF_ARRAY */
                    Alignment = 0x3,
                    Flags = NDR64_ARRAY_FLAGS.None,
                    Reserved = 0,
                    ElementSize = 4,
                    ConfDescriptor = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag44, 0)
                },
                frag2 = new NDR64_ARRAY_ELEMENT_INFO
                {
                    ElementMemSize = 0x4,
                    Element = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag43,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag43, 0),
                true);

            var midlFrag44 = new MIDL_FRAG44_EFSR
            {
                frag1 = 0x1,
                frag2 = new NDR64_EXPR_VAR
                {
                    ExprType = 0x3, /* FC_EXPR_VAR */
                    VarType = 0x1, /* FC64_UINT8 */
                    Reserved = 0,
                    Offset = 0x1
                }
            };
            Marshal.StructureToPtr(
                midlFrag44,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag44, 0),
                true);

            var midlFrag46 = new MIDL_FRAG46_EFSR
            {
                /* EFS_HASH_BLOB */
                frag1 = new NDR64_BOGUS_STRUCTURE_HEADER_FORMAT
                {
                    FormatCode = 0x35, /* FC64_FORCED_BOGUS_STRUCT */
                    Alignment = 0x7,
                    Flags = (NDR64_STRUCTURE_FLAGS)0x3,
                    Reserved = 0,
                    MemorySize = 0x10,
                    OriginalMemberLayout = IntPtr.Zero,
                    OriginalPointerLayout = IntPtr.Zero,
                    PointerLayout = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag50, 0)
                },
                frag2_1 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x5, /* FC64_INT32 */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_2 = new NDR64_MEMPAD_FORMAT
                {
                    FormatCode = 0x90, /* FC64_STRUCTPADN */
                    Reserved1 = 0,
                    MemPad = 0x4,
                    Reserved2 = 0
                },
                frag2_3 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x14, /* FC64_POINTER */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_4 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x93, /* FC64_END */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                }
            };
            Marshal.StructureToPtr(
                midlFrag46,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag46, 0),
                true);

            var midlFrag47 = new MIDL_FRAG47_EFSR
            {
                frag1 = new NDR64_CONF_ARRAY_HEADER_FORMAT
                {
                    FormatCode = 0x41, /* FC64_CONF_ARRAY */
                    Alignment = 0x0,
                    Flags = 0,
                    Reserved = 0,
                    ElementSize = 0x1,
                    ConfDescriptor = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag48, 0)
                },
                frag2 = new NDR64_ARRAY_ELEMENT_INFO
                {
                    ElementMemSize = 0x1,
                    Element = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag95, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag47,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag47, 0),
                true);

            var midlFrag48 = new MIDL_FRAG48_EFSR
            {
                frag1 = 0x5,
                frag2 = new NDR64_RANGE_FORMAT
                {
                    FormatCode = 0xA4, /* FC64_RANGE */
                    RangeType = 0x5, /* FC64_INT32 */
                    Reserved = 0,
                    MinValue = 0,
                    MaxValue = 0x64
                },
                frag3 = new NDR64_EXPR_VAR
                {
                    ExprType = 0x3, /* FC_EXPR_VAR */
                    VarType = 0x6, /* FC64_UINT32 */
                    Reserved = 0,
                    Offset = 0
                }
            };
            Marshal.StructureToPtr(
                midlFrag48,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag48, 0),
                true);

            var midlFrag50 = new MIDL_FRAG50_EFSR
            {
                frag1 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0x20,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag47, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag50,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag50, 0),
                true);

            var midlFrag52 = new MIDL_FRAG52_EFSR
            {
                /* *RPC_SID */
                frag1 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0x20,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag42, 0)
                },
                /* *EFS_HASH_BLOB */
                frag2 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag46, 0)
                },
                /* *wchar_t */
                frag3 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag52,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag52, 0),
                true);

            var midlFrag53 = new MIDL_FRAG53_EFSR
            {
                FormatCode = 0x21, /* FC64_UP */
                Flags = 0,
                Reserved = 0,
                Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag41, 0)
            };
            Marshal.StructureToPtr(
                midlFrag53,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag53, 0),
                true);

            var midlFrag54 = new MIDL_FRAG54_EFSR
            {
                frag1 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0x20,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag39, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag54,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag54, 0),
                true);

            var midlFrag56 = new MIDL_FRAG56_EFSR
            {
                /* procedure EfsRpcQueryRecoveryAgents */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x014E0040,
                    StackSize = 0x20u,
                    ConstantClientBufferSize = 0,
                    ConstantServerBufferSize = 0x8u,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x3,
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
                    NotifyIndex = 0,
                },
                /* parameter FileName */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x8
                },
                /* parameter RecoveryAgents */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag59, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x8013,
                    Reserved = 0,
                    StackOffset = 0x10
                },
                /* parameter DWORD */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x18
                }
            };
            Marshal.StructureToPtr(
                midlFrag56,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag56, 0),
                true);

            var midlFrag59 = new MIDL_FRAG59_EFSR
            {
                FormatCode = 0x20, /* FC64_RP */
                Flags = 0x14,
                Reserved = 0,
                Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag60, 0)
            };
            Marshal.StructureToPtr(
                midlFrag59,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag59, 0),
                true);

            var midlFrag60 = new MIDL_FRAG60_EFSR
            {
                FormatCode = 0x21, /* FC64_UP */
                Flags = 0,
                Reserved = 0,
                Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag38, 0)
            };
            Marshal.StructureToPtr(
                midlFrag60,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag60, 0),
                true);

            var midlFrag62 = new MIDL_FRAG62_EFSR
            {
                /* procedure EfsRpcRemoveUsersFromFile */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x012c0040,
                    StackSize = 0x20u,
                    ConstantClientBufferSize = 0,
                    ConstantServerBufferSize = 0x8u,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x3,
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
                    NotifyIndex = 0,
                },
                /* parameter FileName */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x8
                },
                /* parameter Users */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag38, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x10
                },
                /* parameter DWORD */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x18
                }
            };
            Marshal.StructureToPtr(
                midlFrag62,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag62, 0),
                true);

            var midlFrag67 = new MIDL_FRAG67_EFSR
            {
                /* procedure EfsRpcAddUsersToFile */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x012C0040,
                    StackSize = 0x20u,
                    ConstantClientBufferSize = 0,
                    ConstantServerBufferSize = 0x8u,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x3,
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
                    NotifyIndex = 0,
                },
                /* parameter FileName */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x8
                },
                /* parameter EncryptionCertificates */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x10
                },
                /* parameter DWORD */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x18
                }
            };
            Marshal.StructureToPtr(
                midlFrag67,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag67, 0),
                true);

            var midlFrag71 = new MIDL_FRAG71_EFSR
            {
                /* ENCRYPTION_CERTIFICATE_LIST */
                frag1 = new NDR64_BOGUS_STRUCTURE_HEADER_FORMAT
                {
                    FormatCode = 0x35, /* FC64_FORCED_BOGUS_STRUCT */
                    Alignment = 0x7,
                    Flags = (NDR64_STRUCTURE_FLAGS)0x3,
                    Reserved = 0,
                    MemorySize = 0x10u,
                    OriginalMemberLayout = IntPtr.Zero,
                    OriginalPointerLayout = IntPtr.Zero,
                    PointerLayout = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag81, 0)
                },
                frag2_1 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x5, /* FC64_INT32 */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_2 = new NDR64_MEMPAD_FORMAT
                {
                    FormatCode = 0x90, /* FC64_STRUCTPADN */
                    Reserved1 = 0,
                    MemPad = 0x4,
                    Reserved2 = 0
                },
                frag2_3 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x14, /* FC64_POINTER */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_4 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x93, /* FC64_END */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                }
            };
            Marshal.StructureToPtr(
                midlFrag71,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                true);

            var midlFrag72 = new MIDL_FRAG72_EFSR
            {
                /* **ENCRYPTION_CERTIFICATE */
                frag1 = new NDR64_CONF_ARRAY_HEADER_FORMAT
                {
                    FormatCode = 0x41, /* FC64_CONF_ARRAY */
                    Alignment = 0x7,
                    Flags = (NDR64_ARRAY_FLAGS)0x1,
                    Reserved = 0,
                    ElementSize = 0x8,
                    ConfDescriptor = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag73, 0)
                },
                frag2_1 = new NDR64_REPEAT_FORMAT
                {
                    FormatCode = 0x82, /* FC64_VARIABLE_REPEAT */
                    Flags = NDR64_POINTER_REPEAT_FLAGS.None,
                    Reserved = 0,
                    Increment = 0x8u,
                    OffsetToArray = 0,
                    NumberOfPointers = 0x1u
                },
                frag2_2_1 = new NDR64_POINTER_INSTANCE_HEADER_FORMAT
                {
                    Offset = 0,
                    Reserved = 0
                },
                frag2_2_2 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag74, 0)
                },
                frag2_3 = 0x93, /* FC64_END */
                frag3 = new NDR64_ARRAY_ELEMENT_INFO
                {
                    ElementMemSize = 0x8,
                    Element = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag80, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag72,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag72, 0),
                true);

            var midlFrag73 = new MIDL_FRAG73_EFSR
            {
                frag1 = 0x5u,
                frag2 = new NDR64_RANGE_FORMAT
                {
                    FormatCode = 0xA4, /* FC64_RANGE */
                    RangeType = 0x4, /* FC64_INT32 */
                    Reserved = 0,
                    MinValue = 0,
                    MaxValue = 0x1F4
                },
                frag3 = new NDR64_EXPR_VAR
                {
                    ExprType = 0x3, /* FC_EXPR_VAR */
                    VarType = 0x6, /* FC64_UINT32 */
                    Reserved = 0,
                    Offset = 0
                }
            };
            Marshal.StructureToPtr(
                midlFrag73,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag73, 0),
                true);

            var midlFrag74 = new MIDL_FRAG74_EFSR
            {
                /* ENCRYPTION_CERTIFICATE */
                frag1 = new NDR64_BOGUS_STRUCTURE_HEADER_FORMAT
                {
                    FormatCode = 0x35, /* FC64_FORCED_BOGUS_STRUCT */
                    Alignment = 0x7,
                    Flags = (NDR64_STRUCTURE_FLAGS)0x3, /* ENCRYPTION_CERTIFICATE_HASH */
                    Reserved = 0,
                    MemorySize = 0x18u,
                    OriginalMemberLayout = IntPtr.Zero,
                    OriginalPointerLayout = IntPtr.Zero,
                    PointerLayout = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag79, 0)
                },
                frag2_1 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x5, /* FC64_INT32 */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_2 = new NDR64_MEMPAD_FORMAT
                {
                    FormatCode = 0x90, /* FC64_STRUCTPADN */
                    Reserved1 = 0,
                    MemPad = 0x4,
                    Reserved2 = 0
                },
                frag2_3 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x14, /* FC64_POINTER */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_4 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x14, /* FC64_POINTER */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_5 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x93, /* FC64_END */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                }
            };
            Marshal.StructureToPtr(
                midlFrag74,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag74, 0),
                true);

            var midlFrag75 = new MIDL_FRAG75_EFSR
            {
                /* EFS_CERTIFICATE_BLOB */
                frag1 = new NDR64_STRUCTURE_HEADER_FORMAT
                {
                    FormatCode = 0x31, /* FC64_PSTRUCT */
                    Alignment = 0x7,
                    Flags = NDR64_STRUCTURE_FLAGS.HasPointerInfo,
                    Reserved = 0,
                    MemorySize = 0x10
                },
                frag2_1 = new NDR64_NO_REPEAT_FORMAT
                {
                    FormatCode = 0x80, /* FC64_NO_REPEAT */
                    Flags = 0,
                    Reserved1 = 0,
                    Reserved2 = 0
                },
                frag2_2 = new NDR64_POINTER_INSTANCE_HEADER_FORMAT
                {
                    Offset = 0x8,
                    Reserved = 0
                },
                frag2_3 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0x20,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag76, 0)
                },
                frag2_4 = 0x93 /* FC64_END */
            };
            Marshal.StructureToPtr(
                midlFrag75,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag75, 0),
                true);

            var midlFrag76 = new MIDL_FRAG76_EFSR
            {
                frag1 = new NDR64_CONF_ARRAY_HEADER_FORMAT
                {
                    FormatCode = 0x41, /* FC64_CONF_ARRAY */
                    Alignment = 0,
                    Flags = 0,
                    Reserved = 0,
                    ElementSize = 1,
                    ConfDescriptor = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag77, 0)
                },
                frag2 = new NDR64_ARRAY_ELEMENT_INFO
                {
                    ElementMemSize = 1,
                    Element = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag95, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag76,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag76, 0),
                true);

            var midlFrag77 = new MIDL_FRAG77_EFSR
            {
                frag1 = 0x5,
                frag2 = new NDR64_RANGE_FORMAT
                {
                    FormatCode = 0xA4, /* FC64_RANGE */
                    RangeType = 0x5, /* FC64_INT32 */
                    Reserved = 0,
                    MinValue = 0,
                    MaxValue = 0x8000
                },
                frag3 = new NDR64_EXPR_VAR
                {
                    ExprType = 0x3, /* FC_EXPR_VAR */
                    VarType = 0x6, /* FC64_UINT32 */
                    Reserved = 0,
                    Offset = 0x4
                }
            };
            Marshal.StructureToPtr(
                midlFrag77,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag77, 0),
                true);

            var midlFrag79 = new MIDL_FRAG79_EFSR
            {
                /* *RPC_SID */
                frag1 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag42, 0)
                },
                /* *EFS_CERTIFICATE_BLOB */
                frag2 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag75, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag79,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag79, 0),
                true);

            var midlFrag80 = new MIDL_FRAG80_EFSR
            {
                FormatCode = 0x21, /* FC64_UP */
                Flags = 0,
                Reserved = 0,
                Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag74, 0)
            };
            Marshal.StructureToPtr(
                midlFrag80,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag80, 0),
                true);

            var midlFrag81 = new MIDL_FRAG81_EFSR
            {
                /* **ENCRYPTION_CERTIFICATE */
                frag1 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0x20,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag72, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag81,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag81, 0),
                true);

            var midlFrag92 = new MIDL_FRAG92_EFSR
            {
                /* EFS_RPC_BLOB */
                frag1 = new NDR64_BOGUS_STRUCTURE_HEADER_FORMAT
                {
                    FormatCode = 0x35, /* FC64_FORCED_BOGUS_STRUCT */
                    Alignment = 0x7,
                    Flags = (NDR64_STRUCTURE_FLAGS)0x3,
                    Reserved = 0,
                    MemorySize = 0x10u,
                    OriginalMemberLayout = IntPtr.Zero,
                    OriginalPointerLayout = IntPtr.Zero,
                    PointerLayout = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag96, 0)
                },
                frag2_1 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x5, /* FC64_INT32 */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_2 = new NDR64_MEMPAD_FORMAT
                {
                    FormatCode = 0x90, /* FC64_STRUCTPADN */
                    Reserved1 = 0,
                    MemPad = 0x4,
                    Reserved2 = 0
                },
                frag2_3 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x14, /* FC64_POINTER */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_4 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x93, /* FC64_END */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                }
            };
            Marshal.StructureToPtr(
                midlFrag92,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag92, 0),
                true);

            var midlFrag93 = new MIDL_FRAG93_EFSR
            {
                frag1 = new NDR64_CONF_ARRAY_HEADER_FORMAT
                {
                    FormatCode = 0x41, /* FC64_CONF_ARRAY */
                    Alignment = 0,
                    Flags = 0,
                    Reserved = 0,
                    ElementSize = 0x1,
                    ConfDescriptor = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag94, 0)
                },
                frag2 = new NDR64_ARRAY_ELEMENT_INFO
                {
                    ElementMemSize = 0x1,
                    Element = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag95, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag93,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag93, 0),
                true);

            var midlFrag94 = new MIDL_FRAG94_EFSR
            {
                frag1 = 0x5,
                frag2 = new NDR64_RANGE_FORMAT
                {
                    FormatCode = 0xA4, /* FC64_RANGE */
                    RangeType = 0x5, /* FC64_INT32 */
                    Reserved = 0,
                    MinValue = 0,
                    MaxValue = 0x41000
                },
                frag3 = new NDR64_EXPR_VAR
                {
                    ExprType = 0x3, /* FC_EXPR_VAR */
                    VarType = 0x6, /* FC64_UINT32 */
                    Reserved = 0,
                    Offset = 0
                }
            };
            Marshal.StructureToPtr(
                midlFrag94,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag94, 0),
                true);

            MidlFrag95[0] = 0x10; /* FC64_CHAR */

            var midlFrag96 = new MIDL_FRAG96_EFSR
            {
                frag1 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0x20,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag93, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag96,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag96, 0),
                true);

            var midlFrag99 = new MIDL_FRAG99_EFSR
            {
                /* procedure EfsRpcFileKeyInfo */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x014E0040,
                    StackSize = 0x28u,
                    ConstantClientBufferSize = 0x8u,
                    ConstantServerBufferSize = 0x8u,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x4,
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
                    NotifyIndex = 0,
                },
                /* parameter FileName */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x8
                },
                /* parameter InfoClass */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00C8,
                    Reserved = 0,
                    StackOffset = 0x10
                },
                /* parameter KeyInfo */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag137, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x8013,
                    Reserved = 0,
                    StackOffset = 0x18
                },
                /* parameter DWORD */
                frag6 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x20
                }
            };
            Marshal.StructureToPtr(
                midlFrag99,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag99, 0),
                true);

            var midlFrag106 = new MIDL_FRAG106_EFSR
            {
                /* procedure EfsRpcDuplicateEncryptionInfoFile */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x012C0040u,
                    StackSize = 0x40u,
                    ConstantClientBufferSize = 0x18u,
                    ConstantServerBufferSize = 0x8u,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x7,
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
                    NotifyIndex = 0,
                },
                /* parameter SrcFileName */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x8
                },
                /* parameter DestFileName */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x10
                },
                /* parameter dwCreationDisposition */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00C8,
                    Reserved = 0,
                    StackOffset = 0x18
                },
                /* parameter dwAttributes */
                frag6 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00C8,
                    Reserved = 0,
                    StackOffset = 0x20
                },
                /* parameter RelativeSD */
                frag7 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag143, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x000B,
                    Reserved = 0,
                    StackOffset = 0x28
                },
                /* parameter bInheritHandle */
                frag8 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00C8,
                    Reserved = 0,
                    StackOffset = 0x30
                },
                /* parameter DWORD */
                frag9 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x38
                }
            };
            Marshal.StructureToPtr(
                midlFrag106,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag106, 0),
                true);

            var midlFrag117 = new MIDL_FRAG117_EFSR
            {
                /* procedure EfsRpcAddUsersToFileEx */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x012C0040u,
                    StackSize = 0x30u,
                    ConstantClientBufferSize = 0x8u,
                    ConstantServerBufferSize = 0x8u,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x5,
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
                    NotifyIndex = 0,
                },
                /* parameter dwFlags */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00C8,
                    Reserved = 0,
                    StackOffset = 0x8
                },
                /* parameter Reserved */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag143, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x000B,
                    Reserved = 0,
                    StackOffset = 0x10
                },
                /* parameter FileName */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x18
                },
                /* parameter EncryptionCertificates */
                frag6 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag71, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x20
                },
                /* parameter DWORD */
                frag7 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x28
                }
            };
            Marshal.StructureToPtr(
                midlFrag117,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag117, 0),
                true);

            var midlFrag124 = new MIDL_FRAG124_EFSR
            {
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x016E0040u,
                    StackSize = 0x38u,
                    ConstantClientBufferSize = 0x10u,
                    ConstantServerBufferSize = 0x8u,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x6,
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
                    NotifyIndex = 0,
                },
                /* parameter dwFileKeyInfoFlags */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00C8,
                    Reserved = 0,
                    StackOffset = 0x8
                },
                /* parameter Reserved */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag143, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x000B,
                    Reserved = 0,
                    StackOffset = 0x10
                },
                /* parameter FileName */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x18
                },
                /* parameter InfoClass */
                frag6 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00C8,
                    Reserved = 0,
                    StackOffset = 0x20
                },
                /* parameter KeyInfo */
                frag7 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag137, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x8013,
                    Reserved = 0,
                    StackOffset = 0x28
                },
                frag8 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x30
                }
            };
            Marshal.StructureToPtr(
                midlFrag124,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag124, 0),
                true);

            var midlFrag134 = new MIDL_FRAG134_EFSR
            {
                /* procedure EfsRpcGetEncryptedFileMetadata */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x014E0040,
                    StackSize = 0x20u,
                    ConstantClientBufferSize = 0,
                    ConstantServerBufferSize = 0x8u,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x3,
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
                    NotifyIndex = 0,
                },
                /* parameter FileName */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x8
                },
                /* parameter EfsStreamBlob */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag137, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x8013,
                    Reserved = 0,
                    StackOffset = 0x10
                },
                /* parameter DWORD */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x18
                }
            };
            Marshal.StructureToPtr(
                midlFrag134,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag134, 0),
                true);

            var midlFrag137 = new MIDL_FRAG137_EFSR
            {
                FormatCode = 0x20, /* FC64_RP */
                Flags = 0x14,
                Reserved = 0,
                Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag143, 0)
            };
            Marshal.StructureToPtr(
                midlFrag137,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag137, 0),
                true);

            var midlFrag140 = new MIDL_FRAG140_EFSR
            {
                /* procedure EfsRpcSetEncryptedFileMetadata */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x012C0040u,
                    StackSize = 0x30u,
                    ConstantClientBufferSize = 0,
                    ConstantServerBufferSize = 0x8u,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x5,
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
                    NotifyIndex = 0,
                },
                /* parameter FileName */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x8
                },
                /* parameter OldEfsStreamBlob */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag143, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x000B,
                    Reserved = 0,
                    StackOffset = 0x10
                },
                /* parameter NewEfsStreamBlob */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag92, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x18
                },
                /* parameter NewEfsSignature */
                frag6 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag145, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x000B,
                    Reserved = 0,
                    StackOffset = 0x20
                },
                /* parameter DWORD */
                frag7 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x28
                }
            };
            Marshal.StructureToPtr(
                midlFrag140,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag140, 0),
                true);

            var midlFrag143 = new MIDL_FRAG143_EFSR
            {
                /* *EFS_RPC_BLOB */
                FormatCode = 0x21, /* FC64_UP */
                Flags = 0,
                Reserved = 0,
                Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag92, 0)
            };
            Marshal.StructureToPtr(
                midlFrag143,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag143, 0),
                true);

            var midlFrag145 = new MIDL_FRAG145_EFSR
            {
                FormatCode = 0x21, /* FC64_UP */
                Flags = 0,
                Reserved = 0,
                Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag146, 0)
            };
            Marshal.StructureToPtr(
                midlFrag145,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag145, 0),
                true);

            var midlFrag146 = new MIDL_FRAG146_EFSR
            {
                /* ENCRYPTED_FILE_METADATA_SIGNATURE */
                frag1 = new NDR64_BOGUS_STRUCTURE_HEADER_FORMAT
                {
                    FormatCode = 0x35, /* FC64_FORCED_BOGUS_STRUCT */
                    Alignment = 0x7,
                    Flags = (NDR64_STRUCTURE_FLAGS)0x3, /* ENCRYPTION_CERTIFICATE_HASH */
                    Reserved = 0,
                    MemorySize = 0x20u,
                    OriginalMemberLayout = IntPtr.Zero,
                    OriginalPointerLayout = IntPtr.Zero,
                    PointerLayout = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag147, 0)
                },
                frag2_1 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x5, /* FC64_INT32 */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_2 = new NDR64_MEMPAD_FORMAT
                {
                    FormatCode = 0x90, /* FC64_STRUCTPADN */
                    Reserved1 = 0,
                    MemPad = 0x4,
                    Reserved2 = 0
                },
                frag2_3 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x14, /* FC64_POINTER */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_4 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x14, /* FC64_POINTER */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_5 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x14, /* FC64_POINTER */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_6 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x93, /* FC64_END */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                }
            };
            Marshal.StructureToPtr(
                midlFrag146,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag146, 0),
                true);

            var midlFrag147 = new MIDL_FRAG147_EFSR
            {
                /* ENCRYPTED_FILE_METADATA_SIGNATURE */
                frag1 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag38, 0)
                },
                frag2 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag74, 0)
                },
                frag3 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag92, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag147,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag147, 0),
                true);

            var midlFrag149 = new MIDL_FRAG149_EFSR
            {
                /* procedure EfsRpcFlushEfsCache */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x01080040u,
                    StackSize = 0x10u,
                    ConstantClientBufferSize = 0x0u,
                    ConstantServerBufferSize = 0x8u,
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
                    NotifyIndex = 0,
                },
                /* parameter DWORD */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x8
                }
            };
            Marshal.StructureToPtr(
                midlFrag149,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag149, 0),
                true);

            var midlFrag151 = new MIDL_FRAG151_EFSR
            {
                /* procedure EfsRpcEncryptFileExSrv */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x010C0040u,
                    StackSize = 0x28u,
                    ConstantClientBufferSize = 0x8u,
                    ConstantServerBufferSize = 0x8u,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x4,
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
                    NotifyIndex = 0,
                },
                /* parameter FileName */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x8
                },
                /* parameter ProtectorDescriptor */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag154, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x000B,
                    Reserved = 0,
                    StackOffset = 0x10
                },
                /* parameter Flags */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00C8,
                    Reserved = 0,
                    StackOffset = 0x18
                },
                /* parameter long */
                frag6 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x20
                }
            };
            Marshal.StructureToPtr(
                midlFrag151,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag151, 0),
                true);

            var midlFrag154 = new MIDL_FRAG154_EFSR
            {
                /* *wchar_t */
                FormatCode = 0x21, /* FC64_UP */
                Flags = 0,
                Reserved = 0,
                Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0)
            };
            Marshal.StructureToPtr(
                midlFrag154,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag154, 0),
                true);

            var midlFrag158 = new MIDL_FRAG158_EFSR
            {
                /* procedure EfsRpcQueryProtectors */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x014E0040u,
                    StackSize = 0x20u,
                    ConstantClientBufferSize = 0x0u,
                    ConstantServerBufferSize = 0x8u,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0x3,
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
                    NotifyIndex = 0,
                },
                /* parameter FileName */
                frag3 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x010B,
                    Reserved = 0,
                    StackOffset = 0x8
                },
                /* parameter ppProtectorList */
                frag4 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag161, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x1013,
                    Reserved = 0,
                    StackOffset = 0x10
                },
                /* parameter DWORD */
                frag5 = new NDR64_PARAM_FORMAT
                {
                    Type = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag172, 0),
                    Attributes = (NDR64_PARAM_FLAGS)0x00F0,
                    Reserved = 0,
                    StackOffset = 0x18
                }
            };
            Marshal.StructureToPtr(
                midlFrag158,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag158, 0),
                true);

            var midlFrag161 = new MIDL_FRAG161_EFSR
            {
                /* ***_ENCRYPTION_PROTECTOR_LIST */
                FormatCode = 0x20, /* FC64_RP */
                Flags = 0x14,
                Reserved = 0,
                Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag162, 0)
            };
            Marshal.StructureToPtr(
                midlFrag161,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag161, 0),
                true);

            var midlFrag163 = new MIDL_FRAG163_EFSR
            {
                /* *_ENCRYPTION_PROTECTOR_LIST */
                FormatCode = 0x21, /* FC64_UP */
                Flags = 0,
                Reserved = 0,
                Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag164, 0)
            };
            Marshal.StructureToPtr(
                midlFrag163,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag163, 0),
                true);

            var midlFrag164 = new MIDL_FRAG164_EFSR
            {
                /* _ENCRYPTION_PROTECTOR_LIST */
                frag1 = new NDR64_BOGUS_STRUCTURE_HEADER_FORMAT
                {
                    FormatCode = 0x35, /* FC64_FORCED_BOGUS_STRUCT */
                    Alignment = 0x7,
                    Flags = (NDR64_STRUCTURE_FLAGS)0x3,
                    Reserved = 0,
                    MemorySize = 0x10u,
                    OriginalMemberLayout = IntPtr.Zero,
                    OriginalPointerLayout = IntPtr.Zero,
                    PointerLayout = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag171, 0)
                },
                frag2_1 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x5, /* FC64_INT32 */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_2 = new NDR64_MEMPAD_FORMAT
                {
                    FormatCode = 0x90, /* FC64_STRUCTPADN */
                    Reserved1 = 0,
                    MemPad = 0x4,
                    Reserved2 = 0
                },
                frag2_3 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x14, /* FC64_POINTER */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_4 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x93, /* FC64_END */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                }
            };
            Marshal.StructureToPtr(
                midlFrag164,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag164, 0),
                true);

            var midlFrag165 = new MIDL_FRAG165_EFSR
            {
                /* **_ENCRYPTION_PROTECTOR */
                frag1 = new NDR64_CONF_ARRAY_HEADER_FORMAT
                {
                    FormatCode = 0x41, /* FC64_CONF_ARRAY */
                    Alignment = 0x7,
                    Flags = (NDR64_ARRAY_FLAGS)0x1,
                    Reserved = 0,
                    ElementSize = 0x8,
                    ConfDescriptor = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag166, 0)
                },
                frag2_1 = new NDR64_REPEAT_FORMAT
                {
                    FormatCode = 0x82, /* FC64_VARIABLE_REPEAT */
                    Flags = NDR64_POINTER_REPEAT_FLAGS.None,
                    Reserved = 0,
                    Increment = 0x8u,
                    OffsetToArray = 0,
                    NumberOfPointers = 0x1u
                },
                frag2_2_1 = new NDR64_POINTER_INSTANCE_HEADER_FORMAT
                {
                    Offset = 0,
                    Reserved = 0
                },
                frag2_2_2 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag167, 0)
                },
                frag2_3 = 0x93, /* FC64_END */
                frag3 = new NDR64_ARRAY_ELEMENT_INFO
                {
                    ElementMemSize = 0x8,
                    Element = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag170, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag165,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag165, 0),
                true);

            var midlFrag166 = new MIDL_FRAG166_EFSR
            {
                frag1 = 0x1,
                frag2 = new NDR64_EXPR_VAR
                {
                    ExprType = 0x3, /* FC_EXPR_VAR */
                    VarType = 0x6, /* FC64_UINT32 */
                    Reserved = 0,
                    Offset = 0
                }
            };
            Marshal.StructureToPtr(
                midlFrag166,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag166, 0),
                true);

            var midlFrag167 = new MIDL_FRAG167_EFSR
            {
                /* _ENCRYPTION_PROTECTOR */
                frag1 = new NDR64_BOGUS_STRUCTURE_HEADER_FORMAT
                {
                    FormatCode = 0x35, /* FC64_FORCED_BOGUS_STRUCT */
                    Alignment = 0x7,
                    Flags = (NDR64_STRUCTURE_FLAGS)0x3, /* ENCRYPTION_CERTIFICATE_HASH */
                    Reserved = 0,
                    MemorySize = 0x18u,
                    OriginalMemberLayout = IntPtr.Zero,
                    OriginalPointerLayout = IntPtr.Zero,
                    PointerLayout = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag169, 0)
                },
                frag2_1 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x5, /* FC64_INT32 */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_2 = new NDR64_MEMPAD_FORMAT
                {
                    FormatCode = 0x90, /* FC64_STRUCTPADN */
                    Reserved1 = 0,
                    MemPad = 0x4,
                    Reserved2 = 0
                },
                frag2_3 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x14, /* FC64_POINTER */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_4 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x14, /* FC64_POINTER */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                },
                frag2_5 = new NDR64_SIMPLE_MEMBER_FORMAT
                {
                    FormatCode = 0x93, /* FC64_END */
                    Reserved1 = 0,
                    Reserved2 = 0,
                    Reserved3 = 0
                }
            };
            Marshal.StructureToPtr(
                midlFrag167,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag167, 0),
                true);

            var midlFrag168 = new MIDL_FRAG168_EFSR
            {
                /* *wchar_t */
                Header = new NDR64_STRING_HEADER_FORMAT
                {
                    FormatCode = 0x64, /* FC64_CONF_WCHAR_STRING */
                    Flags = 0,
                    ElementSize = 0x2
                }
            };
            Marshal.StructureToPtr(
                midlFrag168,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0),
                true);

            var midlFrag169 = new MIDL_FRAG169_EFSR
            {
                /* *RPC_SID */
                frag1 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag42, 0)
                },
                /* *wchar_t */
                frag2 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag168, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag169,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag169, 0),
                true);

            var midlFrag170 = new MIDL_FRAG170_EFSR
            {
                /* *_ENCRYPTION_PROTECTOR */
                FormatCode = 0x21, /* FC64_UP */
                Flags = 0,
                Reserved = 0,
                Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag167, 0)
            };
            Marshal.StructureToPtr(
                midlFrag170,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag170, 0),
                true);

            var midlFrag171 = new MIDL_FRAG171_EFSR
            {
                /* **_ENCRYPTION_PROTECTOR */
                frag1 = new NDR64_POINTER_FORMAT
                {
                    FormatCode = 0x21, /* FC64_UP */
                    Flags = 0x20,
                    Reserved = 0,
                    Pointee = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag165, 0)
                }
            };
            Marshal.StructureToPtr(
                midlFrag171,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag171, 0),
                true);

            MidlFrag172[0] = 0x5; /* FC64_INT32 */

            var midlFrag194 = new MIDL_FRAG194_EFSR
            {
                /* procedure Opnum44NotUsedOnWire */
                frag1 = new NDR64_PROC_FORMAT
                {
                    Flags = 0x01000040,
                    StackSize = 0x8u,
                    ConstantClientBufferSize = 0,
                    ConstantServerBufferSize = 0,
                    RpcFlags = 0,
                    FloatDoubleMask = 0,
                    NumberOfParams = 0,
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
                    NotifyIndex = 0,
                }
            };
            Marshal.StructureToPtr(
                midlFrag194,
                Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0),
                true);

            /*
             * Build Ndr64ProcTable
             */
            Ndr64ProcTable[0] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag2, 0);
            Ndr64ProcTable[1] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag9, 0);
            Ndr64ProcTable[2] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag15, 0);
            Ndr64ProcTable[3] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag21, 0);
            Ndr64ProcTable[4] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag24, 0);
            Ndr64ProcTable[5] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag28, 0);
            Ndr64ProcTable[6] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag56, 0);
            Ndr64ProcTable[7] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag56, 0);
            Ndr64ProcTable[8] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag62, 0);
            Ndr64ProcTable[9] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag67, 0);
            Ndr64ProcTable[10] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[11] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag106, 0);
            Ndr64ProcTable[12] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag99, 0);
            Ndr64ProcTable[13] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag106, 0);
            Ndr64ProcTable[14] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[15] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag117, 0);
            Ndr64ProcTable[16] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag124, 0);
            Ndr64ProcTable[17] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[18] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag134, 0);
            Ndr64ProcTable[19] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag140, 0);
            Ndr64ProcTable[20] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag149, 0);
            Ndr64ProcTable[21] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag151, 0);
            Ndr64ProcTable[22] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag158, 0);
            Ndr64ProcTable[23] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[24] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[25] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[26] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[27] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[28] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[29] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[30] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[31] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[32] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[33] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[34] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[35] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[36] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[37] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[38] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[39] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[40] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[41] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[42] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[43] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);
            Ndr64ProcTable[44] = Marshal.UnsafeAddrOfPinnedArrayElement(MidlFrag194, 0);

            /*
             * Build SyntaxInfo
             */
            var syntaxInfo = new MIDL_SYNTAX_INFO[]
            {
                new MIDL_SYNTAX_INFO
                {
                    TransferSyntax = SyntaxIdentifiers.RpcTransferSyntax_2_0,
                    DispatchTable = IntPtr.Zero,
                    ProcString = Marshal.UnsafeAddrOfPinnedArrayElement(MsEfsrConsts.ProcFormatString.Format, 0),
                    FmtStringOffset = Marshal.UnsafeAddrOfPinnedArrayElement(MsEfsrConsts.FormatStringOffsetTable, 0),
                    TypeString = Marshal.UnsafeAddrOfPinnedArrayElement(MsEfsrConsts.TypeFormatString.Format, 0),
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
             * Build RpcClientInterface
             */
            var rpcClientInterface = new RPC_CLIENT_INTERFACE
            {
                Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE)),
                InterfaceId = new RPC_SYNTAX_IDENTIFIER
                {
                    SyntaxGUID = new Guid(EndpointUuidString),
                    SyntaxVersion = new RPC_VERSION { MajorVersion = 1, MinorVersion = 0}
                },
                TransferSyntax = SyntaxIdentifiers.RpcTransferSyntax_2_0,
                DispatchTable = IntPtr.Zero,
                RpcProtseqEndpointCount = 0u,
                RpcProtseqEndpoint = IntPtr.Zero,
                Reserved = UIntPtr.Zero,
                InterpreterInfo = pProxyInfo,
                Flags = 0x02000001u
            };
            Marshal.StructureToPtr(rpcClientInterface, pRpcClientInterface, true);

            /*
             * Build StubDesc
             */
            var stubDesc = new MIDL_STUB_DESC
            {
                RpcInterfaceInformation = pRpcClientInterface,
                pfnAllocate = Marshal.GetFunctionPointerForDelegate((MIDL_USER_ALLOCATE)RpcRoutines.Malloc),
                pfnFree = Marshal.GetFunctionPointerForDelegate((MIDL_USER_FREE)RpcRoutines.Free),
                handleInfo = new IMPLICIT_HANDLE_INFO { pAutoHandle = pAutoBindHandle },
                apfnNdrRundownRoutines = IntPtr.Zero,
                aGenericBindingRoutinePairs = IntPtr.Zero,
                apfnExprEval = IntPtr.Zero,
                aXmitQuintuple = IntPtr.Zero,
                pFormatTypes = Marshal.UnsafeAddrOfPinnedArrayElement(MsEfsrConsts.TypeFormatString.Format, 0),
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
             * Build _RpcTransferSyntax_2_0
             */
            Marshal.StructureToPtr(SyntaxIdentifiers.RpcTransferSyntax_2_0, pRpcTransferSyntax, false);

            /*
             * Build ProxyInfo
             */
            var proxyInfo = new MIDL_STUBLESS_PROXY_INFO
            {
                pStubDesc = pStubDesc,
                ProcFormatString = Marshal.UnsafeAddrOfPinnedArrayElement(MsEfsrConsts.ProcFormatString.Format, 0),
                FormatStringOffset = Marshal.UnsafeAddrOfPinnedArrayElement(MsEfsrConsts.FormatStringOffsetTable, 0),
                pTransferSyntax = pRpcTransferSyntax,
                nCount = new UIntPtr(2u),
                pSyntaxInfo = pSyntaxInfo,
            };
            Marshal.StructureToPtr(proxyInfo, pProxyInfo, true);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(pProxyInfo);
            Marshal.FreeHGlobal(pRpcClientInterface);
            Marshal.FreeHGlobal(pStubDesc);
            Marshal.FreeHGlobal(pAutoBindHandle);
            Marshal.FreeHGlobal(pRpcTransferSyntax);
            Marshal.FreeHGlobal(pSyntaxInfo);
        }

        /*
         * public methods
         */
        public IntPtr GetEfsrBindingHandle(string networkAddress)
        {
            RPC_STATUS rpcStatus;
            IntPtr hBinding = IntPtr.Zero;

            do
            {
                rpcStatus = NativeMethods.RpcStringBindingCompose(
                    EndpointUuidString,
                    "ncacn_np",
                    networkAddress,
                    EndpointPipePath,
                    null,
                    out IntPtr pStringBinding);

                if (rpcStatus != Consts.RPC_S_OK)
                    break;

                rpcStatus = NativeMethods.RpcBindingFromStringBinding(
                    pStringBinding,
                    out hBinding);
                NativeMethods.RpcStringFree(in pStringBinding);

                if (rpcStatus != Consts.RPC_S_OK)
                {
                    hBinding = IntPtr.Zero;
                    break;
                }

                rpcStatus = NativeMethods.RpcBindingSetAuthInfo(
                    hBinding,
                    networkAddress,
                    RPC_C_AUTHN_LEVEL.PKT_PRIVACY,
                    RPC_C_AUTHN.GSS_NEGOTIATE,
                    IntPtr.Zero,
                    RPC_C_AUTHZ.NONE);

                if (rpcStatus != Consts.RPC_S_OK)
                {
                    NativeMethods.RpcBindingFree(ref hBinding);
                    hBinding = IntPtr.Zero;
                }

                rpcStatus = NativeMethods.RpcBindingSetOption(hBinding, RPC_C_OPT.CALL_TIMEOUT, new UIntPtr(1_000_000u));

                if (rpcStatus != Consts.RPC_S_OK)
                {
                    NativeMethods.RpcBindingFree(ref hBinding);
                    hBinding = IntPtr.Zero;
                }
            } while (false);

            return hBinding;
        }

        /*
         * RPC functions
         */
        public RPC_STATUS EfsRpcEncryptFileSrv(
            IntPtr binding_h,
            string /* wchar_t* */ FileName)
        {
            RPC_STATUS rpcStatus;

            try
            {
                IntPtr returnedCode = NativeMethods.NdrClientCall3(
                    pProxyInfo,
                    4,
                    IntPtr.Zero,
                    binding_h,
                    FileName);

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


        public void EfsRpcCloseRaw(ref IntPtr hContext)
        {
            try
            {
                NativeMethods.NdrClientCall3(
                    pProxyInfo,
                    3,
                    IntPtr.Zero,
                    hContext);
            }
            catch (SEHException) { }
        }


        public RPC_STATUS EfsRpcOpenFileRaw(
            IntPtr binding_h,
            out IntPtr hContext,
            string /* wchar_t* */ FileName,
            int Flags)
        {
            RPC_STATUS rpcStatus;
            hContext = IntPtr.Zero;

            try
            {
                IntPtr returnedCode = NativeMethods.NdrClientCall3(
                    pProxyInfo,
                    0,
                    IntPtr.Zero,
                    binding_h,
                    out hContext,
                    FileName,
                    Flags);

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
