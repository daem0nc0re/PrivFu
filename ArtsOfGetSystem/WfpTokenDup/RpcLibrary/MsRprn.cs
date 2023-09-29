using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using RpcLibrary.Interop;

namespace RpcLibrary
{
    using SIZE_T = UIntPtr;
    using MIDL_FRAG8 = NDR64_CONTEXT_HANDLE_FORMAT;
    using MIDL_FRAG9 = NDR64_POINTER_FORMAT;
    using MIDL_FRAG10 = NDR64_CONFORMANT_STRING_FORMAT;
    using RPC_STATUS = Int32;

    internal class MsRprn : IDisposable
    {
        private readonly IntPtr pProxyInfo = IntPtr.Zero;
        private readonly IntPtr pStubDesc = IntPtr.Zero;
        private readonly IntPtr pBindingRoutinePair = IntPtr.Zero;
        private readonly IntPtr pRpcClientInterface = IntPtr.Zero;
        private readonly IntPtr pRpcTransferSyntax = IntPtr.Zero;
        private readonly IntPtr pFormatStringOffsetTable = IntPtr.Zero;
        private readonly IntPtr pAutoHandle = IntPtr.Zero;
        private readonly IntPtr pSyntaxInfo = IntPtr.Zero; // Locate 2 pointers (MIDL_SYNTAX_INFO)
        private readonly IntPtr pNdr64ProcTable = IntPtr.Zero; // Locate 2 pointers (__midl_frag2, __midl_frag4)
        private readonly Dictionary<string, IntPtr> MidlFragBuffers = new Dictionary<string, IntPtr>();

        /*
         * Constructor and Destructor
         */
        public MsRprn()
        {
            /*
             * Resolve routine APIs
             */
            MIDL_USER_ALLOCATE malloc = MemoryAllocateRoutine;
            MIDL_USER_FREE free = MemoryFreeRoutine;
            IntPtr pMalloc = Marshal.GetFunctionPointerForDelegate(malloc);
            IntPtr pFree = Marshal.GetFunctionPointerForDelegate(free);

            if ((pMalloc == IntPtr.Zero) || (pFree == IntPtr.Zero))
                throw new Exception("Failed to resolve required API address.");

            var bindingRoutinePair = new GENERIC_BINDING_ROUTINE_PAIR();
            var bindingRoutine = (GENERIC_BINDING_ROUTINE)BindingRoutine;
            var unbindRoutine = (GENERIC_UNBIND_ROUTINE)UnbindRoutine;

            bindingRoutinePair.pfnBind = Marshal.GetFunctionPointerForDelegate(bindingRoutine);
            bindingRoutinePair.pfnUnbind = Marshal.GetFunctionPointerForDelegate(unbindRoutine);
            pBindingRoutinePair = Marshal.AllocHGlobal(Marshal.SizeOf(bindingRoutinePair));
            Marshal.StructureToPtr(bindingRoutinePair, pBindingRoutinePair, false);

            /*
             * Allocate required buffers
             */
            var nInfoLength = Marshal.SizeOf(typeof(RPC_SYNTAX_IDENTIFIER));
            pRpcTransferSyntax = Marshal.AllocHGlobal(nInfoLength);
            ZeroMemory(pRpcTransferSyntax, nInfoLength);

            nInfoLength = Marshal.SizeOf(typeof(ushort)) * 2;
            pFormatStringOffsetTable = Marshal.AllocHGlobal(nInfoLength);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_SYNTAX_INFO));
            pSyntaxInfo = Marshal.AllocHGlobal(nInfoLength * 2);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_STUBLESS_PROXY_INFO));
            pProxyInfo = Marshal.AllocHGlobal(nInfoLength);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_STUB_DESC));
            pStubDesc = Marshal.AllocHGlobal(nInfoLength);

            nInfoLength = Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
            pRpcClientInterface = Marshal.AllocHGlobal(nInfoLength);

            pAutoHandle = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pAutoHandle, IntPtr.Zero);

            /*
             * Build winspool_Ndr64ProcTable
             */
            InitializeMidlFragBuffers();
            pNdr64ProcTable = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)) * 2);
            Marshal.WriteIntPtr(pNdr64ProcTable, MidlFragBuffers["__midl_frag2"]);
            Marshal.WriteIntPtr(pNdr64ProcTable, IntPtr.Size, MidlFragBuffers["__midl_frag4"]);

            /*
             * Build _RpcTransferSyntax_2_0
             */
            Marshal.StructureToPtr(MsRprnConsts.RpcTransferSyntax_2_0, pRpcTransferSyntax, false);

            /*
             * Build winspool_FormatStringOffsetTable
             */
            for (var idx = 0; idx < 2; idx++)
                Marshal.WriteInt16(pFormatStringOffsetTable, 2 * idx, (short)MsRprnConsts.FormatStringOffsetTable[idx]);

            /*
             * Build winspool_SyntaxInfo
             */
            var syntaxInfo = new MIDL_SYNTAX_INFO
            {
                TransferSyntax = MsRprnConsts.RpcTransferSyntax_2_0,
                DispatchTable = IntPtr.Zero,
                ProcString = Marshal.UnsafeAddrOfPinnedArrayElement(MsRprnConsts.ms2Drprn__MIDL_ProcFormatString.Format, 0),
                FmtStringOffset = pFormatStringOffsetTable,
                TypeString = Marshal.UnsafeAddrOfPinnedArrayElement(MsRprnConsts.ms2Drprn__MIDL_TypeFormatString.Format, 0),
                aUserMarshalQuadruple = IntPtr.Zero,
                pMethodProperties = IntPtr.Zero,
                pReserved2 = UIntPtr.Zero
            };

            Marshal.StructureToPtr(syntaxInfo, pSyntaxInfo, false);

            IntPtr pSyntaxInfo1;
            syntaxInfo.TransferSyntax = MsRprnConsts.RpcTransferSyntax64_2_0;
            syntaxInfo.ProcString = IntPtr.Zero;
            syntaxInfo.FmtStringOffset = pNdr64ProcTable;
            syntaxInfo.TypeString = IntPtr.Zero;

            if (Environment.Is64BitProcess)
                pSyntaxInfo1 = new IntPtr(pSyntaxInfo.ToInt64() + Marshal.SizeOf(syntaxInfo));
            else
                pSyntaxInfo1 = new IntPtr(pSyntaxInfo.ToInt32() + Marshal.SizeOf(syntaxInfo));

            Marshal.StructureToPtr(syntaxInfo, pSyntaxInfo1, false);

            /*
             * Build winspool___RpcClientInterface
             */
            var rpcClientInterface = new RPC_CLIENT_INTERFACE(
                MsRprnConsts.RpcUuidSyntax_1_0,
                MsRprnConsts.RpcTransferSyntax_2_0,
                pProxyInfo);
            Marshal.StructureToPtr(rpcClientInterface, pRpcClientInterface, true);

            /*
             * Build winspool_StubDesc
             */
            var stubDesc = new MIDL_STUB_DESC(
                pRpcClientInterface,
                pMalloc,
                pFree,
                pAutoHandle,
                Marshal.UnsafeAddrOfPinnedArrayElement(MsRprnConsts.ms2Drprn__MIDL_TypeFormatString.Format, 0),
                pBindingRoutinePair,
                pProxyInfo);
            Marshal.StructureToPtr(stubDesc, pStubDesc, false);

            /*
             * Build winspool_ProxyInfo
             */
            var proxyInfo = new MIDL_STUBLESS_PROXY_INFO
            {
                pStubDesc = pStubDesc,
                ProcFormatString = Marshal.UnsafeAddrOfPinnedArrayElement(MsRprnConsts.ms2Drprn__MIDL_ProcFormatString.Format, 0),
                FormatStringOffset = pFormatStringOffsetTable,
                pTransferSyntax = pRpcTransferSyntax,
                nCount = new UIntPtr(2u),
                pSyntaxInfo = pSyntaxInfo
            };
            Marshal.StructureToPtr(proxyInfo, pProxyInfo, true);
        }


        public void Dispose()
        {
            foreach (var buffer in MidlFragBuffers.Values)
            {
                Marshal.FreeHGlobal(buffer);
            }

            Marshal.FreeHGlobal(pRpcTransferSyntax);
            Marshal.FreeHGlobal(pFormatStringOffsetTable);
            Marshal.FreeHGlobal(pNdr64ProcTable);
            Marshal.FreeHGlobal(pSyntaxInfo);
            Marshal.FreeHGlobal(pProxyInfo);
            Marshal.FreeHGlobal(pStubDesc);
            Marshal.FreeHGlobal(pRpcClientInterface);
            Marshal.FreeHGlobal(pAutoHandle);
            Marshal.FreeHGlobal(pBindingRoutinePair);
        }

        /*
         * public functions
         */
        public IntPtr BindingRoutine(IntPtr pRpcString)
        {
            var hBinding = IntPtr.Zero;
            _ = pRpcString;

            try
            {
                do
                {
                    RPC_STATUS rpcStatus = NativeMethods.RpcStringBindingCompose(
                        null,
                        "ncalrpc",
                        null,
                        null,
                        null,
                        out string stringBinding);

                    if (rpcStatus == 0)
                    {
                        rpcStatus = NativeMethods.RpcBindingFromStringBinding(
                            stringBinding,
                            out hBinding);
                        // NativeMethods.RpcStringFree(in stringBinding);

                        if (rpcStatus != 0)
                            hBinding = IntPtr.Zero;
                    }

                    if (hBinding == IntPtr.Zero)
                        break;

                    rpcStatus = NativeMethods.RpcEpResolveBinding(hBinding, pRpcClientInterface);

                    if (rpcStatus != 0)
                    {
                        NativeMethods.RpcBindingFree(ref hBinding);
                        hBinding = IntPtr.Zero;
                    }
                } while (false);
            }
            catch (Exception) { }

            return hBinding;
        }


        public IntPtr MemoryAllocateRoutine(SIZE_T size)
        {
            var nSize = (int)size.ToUInt32();
            return Marshal.AllocHGlobal(nSize);
        }


        public void MemoryFreeRoutine(IntPtr buffer)
        {
            Marshal.FreeHGlobal(buffer);
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
                rpcStatus = returnedCode.ToInt32();
            }
            catch (SEHException) {
                rpcStatus = Marshal.GetExceptionCode();
                hPrinter = IntPtr.Zero;
            }

            return rpcStatus;
        }


        public void UnbindRoutine(IntPtr pServer, IntPtr hBinding)
        {
            _ = pServer;
            NativeMethods.RpcBindingFree(ref hBinding);
        }


        /*
         * private functions
         */
        private void InitializeMidlFragBuffers()
        {
            /*
             * Initialize memory
             */
            var nInfoLength = Marshal.SizeOf(typeof(MIDL_FRAG2));
            var pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
            ZeroMemory(pInfoBuffer, nInfoLength);
            MidlFragBuffers.Add("__midl_frag2", pInfoBuffer);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_FRAG4));
            pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
            ZeroMemory(pInfoBuffer, nInfoLength);
            MidlFragBuffers.Add("__midl_frag4", pInfoBuffer);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_FRAG8));
            pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
            ZeroMemory(pInfoBuffer, nInfoLength);
            MidlFragBuffers.Add("__midl_frag8", pInfoBuffer);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_FRAG9));
            pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
            ZeroMemory(pInfoBuffer, nInfoLength);
            MidlFragBuffers.Add("__midl_frag9", pInfoBuffer);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_FRAG10));
            pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
            ZeroMemory(pInfoBuffer, nInfoLength);
            MidlFragBuffers.Add("__midl_frag10", pInfoBuffer);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_FRAG12));
            pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
            ZeroMemory(pInfoBuffer, nInfoLength);
            MidlFragBuffers.Add("__midl_frag12", pInfoBuffer);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_FRAG13));
            pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
            ZeroMemory(pInfoBuffer, nInfoLength);
            MidlFragBuffers.Add("__midl_frag13", pInfoBuffer);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_FRAG14));
            pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
            ZeroMemory(pInfoBuffer, nInfoLength);
            MidlFragBuffers.Add("__midl_frag14", pInfoBuffer);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_FRAG15));
            pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
            ZeroMemory(pInfoBuffer, nInfoLength);
            MidlFragBuffers.Add("__midl_frag15", pInfoBuffer);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_FRAG16));
            pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
            ZeroMemory(pInfoBuffer, nInfoLength);
            MidlFragBuffers.Add("__midl_frag16", pInfoBuffer);

            nInfoLength = Marshal.SizeOf(typeof(MIDL_FRAG18));
            pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
            ZeroMemory(pInfoBuffer, nInfoLength);
            MidlFragBuffers.Add("__midl_frag18", pInfoBuffer);

            /*
             * Locate midl frag data
             */
            var midl_frag2 = MsRprnConsts.__midl_frag2;
            midl_frag2.frag3.Type = MidlFragBuffers["__midl_frag18"];
            Marshal.StructureToPtr(midl_frag2, MidlFragBuffers["__midl_frag2"], true);

            var midl_frag4 = MsRprnConsts.__midl_frag4;
            midl_frag4.frag3.Type = MidlFragBuffers["__midl_frag9"];
            midl_frag4.frag4.Type = MidlFragBuffers["__midl_frag8"];
            midl_frag4.frag5.Type = MidlFragBuffers["__midl_frag9"];
            midl_frag4.frag6.Type = MidlFragBuffers["__midl_frag12"];
            midl_frag4.frag7.Type = MidlFragBuffers["__midl_frag18"];
            midl_frag4.frag8.Type = MidlFragBuffers["__midl_frag18"];
            Marshal.StructureToPtr(midl_frag4, MidlFragBuffers["__midl_frag4"], true);

            var midl_frag8 = MsRprnConsts.__midl_frag8;
            Marshal.StructureToPtr(midl_frag8, MidlFragBuffers["__midl_frag8"], true);

            var midl_frag9 = MsRprnConsts.__midl_frag9;
            midl_frag9.Pointee = MidlFragBuffers["__midl_frag10"];
            Marshal.StructureToPtr(midl_frag9, MidlFragBuffers["__midl_frag9"], true);

            var midl_frag10 = MsRprnConsts.__midl_frag10;
            Marshal.StructureToPtr(midl_frag10, MidlFragBuffers["__midl_frag10"], true);

            var midl_frag12 = MsRprnConsts.__midl_frag12;
            midl_frag12.frag1.PointerLayout = MidlFragBuffers["__midl_frag16"];
            Marshal.StructureToPtr(midl_frag12, MidlFragBuffers["__midl_frag12"], true);

            var midl_frag13 = MsRprnConsts.__midl_frag13;
            midl_frag13.frag1.ConfDescriptor = MidlFragBuffers["__midl_frag14"];
            midl_frag13.frag2.Element = MidlFragBuffers["__midl_frag15"];
            Marshal.StructureToPtr(midl_frag13, MidlFragBuffers["__midl_frag13"], true);

            var midl_frag14 = MsRprnConsts.__midl_frag14;
            Marshal.StructureToPtr(midl_frag14, MidlFragBuffers["__midl_frag14"], true);

            Marshal.StructureToPtr(MsRprnConsts.__midl_frag15, MidlFragBuffers["__midl_frag15"], false);

            var midl_frag16 = MsRprnConsts.__midl_frag16;
            midl_frag16.frag1.Pointee = MidlFragBuffers["__midl_frag13"];
            Marshal.StructureToPtr(midl_frag16, MidlFragBuffers["__midl_frag16"], true);

            Marshal.StructureToPtr(MsRprnConsts.__midl_frag18, MidlFragBuffers["__midl_frag18"], false);
        }

        private void ZeroMemory(IntPtr Buffer, int Range)
        {
            for (var offset = 0; offset < Range; offset++)
                Marshal.WriteByte(Buffer, offset, 0);
        }
    }
}
