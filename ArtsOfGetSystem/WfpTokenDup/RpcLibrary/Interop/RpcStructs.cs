using System;
using System.Runtime.InteropServices;

namespace RpcLibrary.Interop
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ARRAY_INFO
    {
        public int Dimension;
        public IntPtr /* unsigned long* */ BufferConformanceMark;
        public IntPtr /* unsigned long* */ BufferVarianceMark;
        public IntPtr /* unsigned long* */ MaxCountArray;
        public IntPtr /* unsigned long* */ OffsetArray;
        public IntPtr /* unsigned long* */ ActualCountArray;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct COMM_FAULT_OFFSETS
    {
        public short CommOffset;
        public short FaultOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FULL_PTR_XLAT_TABLES
    {
        public IntPtr RefIdToPointer;
        public IntPtr PointerToRefId;
        public uint NextRefId;
        public XLAT_SIDE XlatSide;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct GENERIC_BINDING_INFO
    {
        public IntPtr pObj;
        public uint Size;
        public IntPtr /* GENERIC_BINDING_ROUTINE */ pfnBind;
        public IntPtr /* GENERIC_UNBIND_ROUTINE */ pfnUnbind;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct GENERIC_BINDING_ROUTINE_PAIR
    {
        public IntPtr /* GENERIC_BINDING_ROUTINE */ pfnBind;
        public IntPtr /* GENERIC_UNBIND_ROUTINE */ pfnUnbind;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct IMPLICIT_HANDLE_INFO
    {
        [FieldOffset(0)]
        public IntPtr /* HANDLE* */ pAutoHandle;

        [FieldOffset(0)]
        public IntPtr /* HANDLE* */ pPrimitiveHandle;

        [FieldOffset(0)]
        public IntPtr /* PGENERIC_BINDING_INFO */ pGenericBindingInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MALLOC_FREE_STRUCT
    {
        public IntPtr pfnAllocate; // void* ( __stdcall * pfnAllocate)(size_t);
        public IntPtr pfnFree; // void ( __stdcall * pfnFree)(void *);
    }

    // Equivalent to NDR64_CONFORMANT_STRING_FORMAT
    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG10
    {
        public NDR64_STRING_HEADER_FORMAT Header;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG12
    {
        public NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
        public MIDL_FRAG12_INNER frag2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG12_INNER
    {
        public NDR64_SIMPLE_MEMBER_FORMAT frag1;
        public NDR64_MEMPAD_FORMAT frag2;
        public NDR64_SIMPLE_MEMBER_FORMAT frag3;
        public NDR64_SIMPLE_MEMBER_FORMAT frag4;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG13
    {
        public NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
        public NDR64_ARRAY_ELEMENT_INFO frag2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG14
    {
        public uint frag1;
        public NDR64_EXPR_VAR frag2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG15
    {
        public byte frag1;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG16
    {
        public NDR64_POINTER_FORMAT frag1;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG18
    {
        public byte frag1;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG2
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG28
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
        public NDR64_PARAM_FORMAT frag4;
        public NDR64_PARAM_FORMAT frag5;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG30
    {
        public NDR64_STRING_HEADER_FORMAT Header;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG4
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
        public NDR64_PARAM_FORMAT frag4;
        public NDR64_PARAM_FORMAT frag5;
        public NDR64_PARAM_FORMAT frag6;
        public NDR64_PARAM_FORMAT frag7;
        public NDR64_PARAM_FORMAT frag8;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG40
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG41
    {
        public byte frag1;
    }

    // Equivalent to NDR64_CONTEXT_HANDLE_FORMAT
    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG8
    {
        public byte FormatCode;
        public byte ContextFlags;
        public byte RundownRoutineIndex;
        public byte Ordinal;
    }

    // Equivalent to NDR64_POINTER_FORMAT
    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG9
    {
        public byte FormatCode;
        public byte Flags;
        public ushort Reserved;
        public IntPtr Pointee;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_INTERFACE_METHOD_PROPERTIES
    {
        public ushort MethodCount;
        public IntPtr /* MIDL_METHOD_PROPERTY_MAP** */ MethodProperties;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_METHOD_PROPERTY
    {
        public uint Id;
        public UIntPtr Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_METHOD_PROPERTY_MAP
    {
        public uint Count;
        public IntPtr /* const MIDL_METHOD_PROPERTY* */ Properties;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_STUBLESS_PROXY_INFO
    {
        public IntPtr /* PMIDL_STUB_DESC */ pStubDesc;
        public IntPtr /* PFORMAT_STRING  (unsiged char *) */ ProcFormatString;
        public IntPtr /* unsigned short* */ FormatStringOffset;
        public IntPtr /* PRPC_SYNTAX_IDENTIFIER */ pTransferSyntax;
        public UIntPtr nCount;
        public IntPtr /* PMIDL_SYNTAX_INFO */ pSyntaxInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_STUB_DESC
    {
        public IntPtr RpcInterfaceInformation;
        public IntPtr pfnAllocate; // void* ( __stdcall * pfnAllocate)(size_t);
        public IntPtr pfnFree; // void ( __stdcall * pfnFree)(void *);
        public IMPLICIT_HANDLE_INFO handleInfo;
        public IntPtr /* NDR_RUNDOWN* */ apfnNdrRundownRoutines;
        public IntPtr /* GENERIC_BINDING_ROUTINE_PAIR* */ aGenericBindingRoutinePairs;
        public IntPtr /* EXPR_EVAL* */ apfnExprEval;
        public IntPtr /* XMIT_ROUTINE_QUINTUPLE* */ aXmitQuintuple;
        public IntPtr /* unsigned char* */ pFormatTypes;
        public int fCheckBounds;
        public uint Version;
        public IntPtr /* MALLOC_FREE_STRUCT* */ pMallocFreeStruct;
        public int MIDLVersion;
        public IntPtr /* COMM_FAULT_OFFSETS* */ CommFaultOffsets;
        public IntPtr /* USER_MARSHAL_ROUTINE_QUADRUPLE* */ aUserMarshalQuadruple;
        public IntPtr /* NDR_NOTIFY_ROUTINE* */ NotifyRoutineTable;
        public UIntPtr mFlags;
        public IntPtr /* NDR_CS_ROUTINES* */ CsRoutineTables;
        public IntPtr ProxyServerInfo;
        public IntPtr /* NDR_EXPR_DESC* */ pExprInfo;

        public MIDL_STUB_DESC(
            IntPtr _pRpcInterfaceInformation,
            IntPtr _pfnAllocate,
            IntPtr _pfnFree,
            IntPtr _pAutoHandle,
            IntPtr _pFormatTypes,
            IntPtr _aGenericBindingRoutinePairs,
            IntPtr _pProxyServerInfo)
        {
            RpcInterfaceInformation = _pRpcInterfaceInformation;
            pfnAllocate = _pfnAllocate;
            pfnFree = _pfnFree;
            handleInfo = new IMPLICIT_HANDLE_INFO { pAutoHandle = _pAutoHandle };
            apfnNdrRundownRoutines = IntPtr.Zero;
            aGenericBindingRoutinePairs = _aGenericBindingRoutinePairs;
            apfnExprEval = IntPtr.Zero;
            aXmitQuintuple = IntPtr.Zero;
            pFormatTypes = _pFormatTypes;
            fCheckBounds = 1;
            Version = 0x00060001u;
            pMallocFreeStruct = IntPtr.Zero;
            MIDLVersion = 0x08010274;
            CommFaultOffsets = IntPtr.Zero;
            aUserMarshalQuadruple = IntPtr.Zero;
            NotifyRoutineTable = IntPtr.Zero;
            mFlags = new UIntPtr(0x02000001u);
            CsRoutineTables = IntPtr.Zero;
            ProxyServerInfo = _pProxyServerInfo;
            pExprInfo = IntPtr.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_STUB_MESSAGE
    {
        public IntPtr /* PRPC_MESSAGE */ RpcMsg;
        public IntPtr /* unsigned char* */ Buffer;
        public IntPtr /* unsigned char* */ BufferStart;
        public IntPtr /* unsigned char* */ BufferEnd;
        public IntPtr /* unsigned char* */ BufferMark;
        public uint BufferLength;
        public uint MemorySize;
        public IntPtr /* unsigned char* */ Memory;
        public byte IsClient;
        public byte Pad;
        public ushort uFlags2;
        public int ReuseBuffer;
        public IntPtr /* NDR_ALLOC_ALL_NODES_CONTEXT* */ pAllocAllNodesContext;
        public IntPtr /* NDR_POINTER_QUEUE_STATE* */pPointerQueueState;
        public int IgnoreEmbeddedPointers;
        public IntPtr /* unsigned char* */ PointerBufferMark;
        public byte CorrDespIncrement;
        public byte uFlags;
        public ushort UniquePtrCount;
        public UIntPtr MaxCount;
        public uint Offset;
        public uint ActualCount;
        public IntPtr pfnAllocate;
        public IntPtr pfnFree;
        public IntPtr /* unsigned char* */ StackTop;
        public IntPtr /* unsigned char* */ pPresentedType;
        public IntPtr /* unsigned char* */ pTransmitType;
        public IntPtr SavedHandle;
        public IntPtr /* MIDL_STUB_DESC* */ StubDesc;
        public IntPtr /* FULL_PTR_XLAT_TABLES* */ FullPtrXlatTables;
        public uint FullPtrRefId;
        public uint PointerLength;
        public MIDL_STUB_MESSAGE_FLAGS flags;
        public uint dwDestContext;
        public IntPtr pvDestContext;
        public IntPtr /* NDR_SCONTEXT* */ SavedContextHandles;
        public int ParamNumber;
        public IntPtr /* IRpcChannelBuffer* */ pRpcChannelBuffer;
        public IntPtr /* PARRAY_INFO */ pArrayInfo;
        public IntPtr /* unsigned long* */ SizePtrCountArray;
        public IntPtr /* unsigned long* */ SizePtrOffsetArray;
        public IntPtr /* unsigned long* */ SizePtrLengthArray;
        public IntPtr pArgQueue;
        public uint dwStubPhase;
        public IntPtr LowStackMark;
        public IntPtr /* PNDR_ASYNC_MESSAGE */ pAsyncMsg;
        public IntPtr /* PNDR_CORRELATION_INFO */ pCorrInfo;
        public IntPtr /* unsigned char* */ pCorrMemory;
        public IntPtr pMemoryList;
        public IntPtr pCSInfo;
        public IntPtr /* unsigned char* */ ConformanceMark;
        public IntPtr /* unsigned char* */ VarianceMark;
        public IntPtr Unused;
        public IntPtr /* NDR_PROC_CONTEXT* */ pContext;
        public IntPtr ContextHandleHash;
        public IntPtr pUserMarshalList;
        public IntPtr Reserved51_3;
        public IntPtr Reserved51_4;
        public IntPtr Reserved51_5;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_SYNTAX_INFO
    {
        public RPC_SYNTAX_IDENTIFIER TransferSyntax;
        public IntPtr /* RPC_DISPATCH_TABLE* */ DispatchTable;
        public IntPtr /* PFORMAT_STRING (unsiged char *) */ ProcString;
        public IntPtr /* unsigned short* */ FmtStringOffset;
        public IntPtr /* PFORMAT_STRING (unsiged char *) */ TypeString;
        public IntPtr aUserMarshalQuadruple;
        public IntPtr /* MIDL_INTERFACE_METHOD_PROPERTIES* */ pMethodProperties;
        public UIntPtr pReserved2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR_CS_ROUTINES
    {
        public IntPtr /* NDR_CS_SIZE_CONVERT_ROUTINES* */ pSizeConvertRoutines;
        public IntPtr /* CS_TAG_GETTING_ROUTINE* */ pTagGettingRoutines;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR_CS_SIZE_CONVERT_ROUTINES
    {
        public IntPtr /* CS_TYPE_NET_SIZE_ROUTINE */ pfnNetSize;
        public IntPtr /* CS_TYPE_TO_NETCS_ROUTINE */ pfnToNetCs;
        public IntPtr /* CS_TYPE_LOCAL_SIZE_ROUTINE */ pfnLocalSize;
        public IntPtr /* CS_TYPE_FROM_NETCS_ROUTINE */ pfnFromNetCs;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR_EXPR_DESC
    {
        public IntPtr /* unsigned short* */ pOffset;
        public IntPtr /* PFORMAT_STRING (unsigned char**) */ pFormatExpr;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR_SCONTEXT
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public IntPtr[] pad;
        public IntPtr userContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR64_ARRAY_ELEMENT_INFO
    {
        public uint ElementMemSize;
        public IntPtr Element;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR64_BIND_AND_NOTIFY_EXTENSION
    {
        public NDR64_BIND_CONTEXT Binding;
        public ushort NotifyIndex;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR64_BIND_CONTEXT
    {
        public byte HandleType;
        public byte Flags;
        public ushort StackOffset;
        public byte RoutineIndex;
        public byte Ordinal;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR64_BOGUS_STRUCTURE_HEADER_FORMAT
    {
        public byte FormatCode;
        public byte Alignment;
        public NDR64_STRUCTURE_FLAGS Flags;
        public byte Reserved;
        public uint MemorySize;
        public IntPtr OriginalMemberLayout;
        public IntPtr OriginalPointerLayout;
        public IntPtr PointerLayout;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR64_CONF_ARRAY_HEADER_FORMAT
    {
        public byte FormatCode;
        public byte Alignment;
        public NDR64_ARRAY_FLAGS Flags;
        public byte Reserved;
        public uint ElementSize;
        public IntPtr ConfDescriptor;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR64_CONFORMANT_STRING_FORMAT
    {
        public NDR64_STRING_HEADER_FORMAT Header;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR64_CONTEXT_HANDLE_FORMAT
    {
        public byte FormatCode;
        public byte ContextFlags;
        public byte RundownRoutineIndex;
        public byte Ordinal;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR64_EXPR_VAR
    {
        public byte ExprType;
        public byte VarType;
        public ushort Reserved;
        public uint Offset;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR64_MEMPAD_FORMAT
    {
        public byte FormatCode;
        public byte Reserved1;
        public ushort MemPad;
        public uint Reserved2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR64_PARAM_FORMAT
    {
        public IntPtr Type;
        public NDR64_PARAM_FLAGS Attributes;
        public ushort Reserved;
        public uint StackOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR64_POINTER_FORMAT
    {
        public byte FormatCode;
        public byte Flags;
        public ushort Reserved;
        public IntPtr Pointee;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR64_PROC_FORMAT
    {
        public uint Flags;
        public uint StackSize;
        public uint ConstantClientBufferSize;
        public uint ConstantServerBufferSize;
        public ushort RpcFlags;
        public ushort FloatDoubleMask;
        public ushort NumberOfParams;
        public ushort ExtensionSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR64_SIMPLE_MEMBER_FORMAT
    {
        public byte FormatCode;
        public byte Reserved1;
        public ushort Reserved2;
        public uint Reserved3;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR64_STRING_HEADER_FORMAT
    {
        public byte FormatCode;
        public NDR64_STRING_FLAGS Flags;
        public ushort ElementSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_DISPATCH_TABLE
    {
        public uint DispatchTableCount;
        public IntPtr /* RPC_DISPATCH_FUNCTION* */ DispatchTable;
        public UIntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_MESSAGE
    {
        public IntPtr Handle;
        public uint DataRepresentation;
        public IntPtr Buffer;
        public uint BufferLength;
        public uint ProcNum;
        public IntPtr /* PRPC_SYNTAX_IDENTIFIER */ TransferSyntax;
        public IntPtr RpcInterfaceInformation;
        public IntPtr ReservedForRuntime;
        public IntPtr ManagerEpv;
        public IntPtr ImportContext;
        public uint RpcFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_PROTSEQ_ENDPOINT
    {
        public IntPtr /* unsigned char* */ RpcProtocolSequence;
        public IntPtr /* unsigned char* */ Endpoint;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct USER_MARSHAL_ROUTINE_QUADRUPLE
    {
        public IntPtr /* USER_MARSHAL_SIZING_ROUTINE */ pfnBufferSize;
        public IntPtr /* USER_MARSHAL_MARSHALLING_ROUTINE */ pfnMarshall;
        public IntPtr /* USER_MARSHAL_UNMARSHALLING_ROUTINE */ pfnUnmarshall;
        public IntPtr /* USER_MARSHAL_FREEING_ROUTINE */ pfnFree;
    }
}
