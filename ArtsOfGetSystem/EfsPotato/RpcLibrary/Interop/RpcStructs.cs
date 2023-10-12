using System;
using System.Runtime.InteropServices;

namespace RpcLibrary.Interop
{
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
    internal struct MIDL_FRAG106_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
        public NDR64_PARAM_FORMAT frag4;
        public NDR64_PARAM_FORMAT frag5;
        public NDR64_PARAM_FORMAT frag6;
        public NDR64_PARAM_FORMAT frag7;
        public NDR64_PARAM_FORMAT frag8;
        public NDR64_PARAM_FORMAT frag9;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG117_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
        public NDR64_PARAM_FORMAT frag4;
        public NDR64_PARAM_FORMAT frag5;
        public NDR64_PARAM_FORMAT frag6;
        public NDR64_PARAM_FORMAT frag7;
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
    internal struct MIDL_FRAG124_EFSR
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
    internal struct MIDL_FRAG134_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
        public NDR64_PARAM_FORMAT frag4;
        public NDR64_PARAM_FORMAT frag5;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG137_EFSR
    {
        public byte FormatCode;
        public byte Flags;
        public ushort Reserved;
        public IntPtr Pointee;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG140_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
        public NDR64_PARAM_FORMAT frag4;
        public NDR64_PARAM_FORMAT frag5;
        public NDR64_PARAM_FORMAT frag6;
        public NDR64_PARAM_FORMAT frag7;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG143_EFSR
    {
        public byte FormatCode;
        public byte Flags;
        public ushort Reserved;
        public IntPtr Pointee;
    }

    // Equivalent to NDR64_POINTER_FORMAT
    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG145_EFSR
    {
        public byte FormatCode;
        public byte Flags;
        public ushort Reserved;
        public IntPtr Pointee;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG146_EFSR
    {
        public NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_1;
        public NDR64_MEMPAD_FORMAT frag2_2;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_3;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_4;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_5;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_6;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG147_EFSR
    {
        public NDR64_POINTER_FORMAT frag1;
        public NDR64_POINTER_FORMAT frag2;
        public NDR64_POINTER_FORMAT frag3;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG149_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG15_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
        public NDR64_PARAM_FORMAT frag4;
        public NDR64_PARAM_FORMAT frag5;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG151_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
        public NDR64_PARAM_FORMAT frag4;
        public NDR64_PARAM_FORMAT frag5;
        public NDR64_PARAM_FORMAT frag6;
    }

    // Equivalent to NDR64_POINTER_FORMAT
    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG154_EFSR
    {
        public byte FormatCode;
        public byte Flags;
        public ushort Reserved;
        public IntPtr Pointee;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG158_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
        public NDR64_PARAM_FORMAT frag4;
        public NDR64_PARAM_FORMAT frag5;
    }

    // Equivalent to NDR64_CONTEXT_HANDLE_FORMAT
    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG16_EFSR
    {
        public byte FormatCode;
        public byte ContextFlags;
        public byte RundownRoutineIndex;
        public byte Ordinal;
    }

    // Equivalent to NDR64_POINTER_FORMAT
    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG161_EFSR
    {
        public byte FormatCode;
        public byte Flags;
        public ushort Reserved;
        public IntPtr Pointee;
    }

    // Equivalent to NDR64_POINTER_FORMAT
    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG162_EFSR
    {
        public byte FormatCode;
        public byte Flags;
        public ushort Reserved;
        public IntPtr Pointee;
    }

    // Equivalent to NDR64_POINTER_FORMAT
    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG163_EFSR
    {
        public byte FormatCode;
        public byte Flags;
        public ushort Reserved;
        public IntPtr Pointee;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG164_EFSR
    {
        public NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_1;
        public NDR64_MEMPAD_FORMAT frag2_2;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_3;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_4;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG165_EFSR
    {
        public NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
        public NDR64_REPEAT_FORMAT frag2_1;
        public NDR64_POINTER_INSTANCE_HEADER_FORMAT frag2_2_1;
        public NDR64_POINTER_FORMAT frag2_2_2;
        public byte frag2_3;
        public NDR64_ARRAY_ELEMENT_INFO frag3;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG166_EFSR
    {
        public uint frag1;
        public NDR64_EXPR_VAR frag2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG167_EFSR
    {
        public NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_1;
        public NDR64_MEMPAD_FORMAT frag2_2;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_3;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_4;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_5;
    }

    // Equivalent to NDR64_CONFORMANT_STRING_FORMAT
    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG168_EFSR
    {
        public NDR64_STRING_HEADER_FORMAT Header;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG169_EFSR
    {
        public NDR64_POINTER_FORMAT frag1;
        public NDR64_POINTER_FORMAT frag2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG170_EFSR
    {
        public byte FormatCode;
        public byte Flags;
        public ushort Reserved;
        public IntPtr Pointee;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG171_EFSR
    {
        public NDR64_POINTER_FORMAT frag1;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG172_EFSR
    {
        public byte frag1;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG18_EFSR
    {
        public byte FormatCode;
        public byte Flags;
        public byte Alignment;
        public byte Reserved;
        public IntPtr Type;
        public uint MemorySize;
        public uint BufferSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG194_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG2_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
        public NDR64_PARAM_FORMAT frag4;
        public NDR64_PARAM_FORMAT frag5;
        public NDR64_PARAM_FORMAT frag6;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG21_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
    }

    // Equivalent to NDR64_CONTEXT_HANDLE_FORMAT
    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG23_EFSR
    {
        public byte FormatCode;
        public byte ContextFlags;
        public byte RundownRoutineIndex;
        public byte Ordinal;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG24_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
        public NDR64_PARAM_FORMAT frag4;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG28_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
        public NDR64_PARAM_FORMAT frag4;
        public NDR64_PARAM_FORMAT frag5;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG38_EFSR
    {
        public NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_1;
        public NDR64_MEMPAD_FORMAT frag2_2;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_3;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_4;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG39_EFSR
    {
        public NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
        public NDR64_REPEAT_FORMAT frag2_1;
        public NDR64_POINTER_INSTANCE_HEADER_FORMAT frag2_2_1;
        public NDR64_POINTER_FORMAT frag2_2_2;
        public byte frag2_3;
        public NDR64_ARRAY_ELEMENT_INFO frag3;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG41_EFSR
    {
        public NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_1;
        public NDR64_MEMPAD_FORMAT frag2_2;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_3;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_4;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_5;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_6;
    }

    // Equivalent to NDR64_CONTEXT_HANDLE_FORMAT
    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG4_EFSR
    {
        public byte FormatCode;
        public byte ContextFlags;
        public byte RundownRoutineIndex;
        public byte Ordinal;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG42_EFSR
    {
        public NDR64_CONF_STRUCTURE_HEADER_FORMAT frag1;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG43_EFSR
    {
        public NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
        public NDR64_ARRAY_ELEMENT_INFO frag2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG44_EFSR
    {
        public uint frag1;
        public NDR64_EXPR_VAR frag2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG46_EFSR
    {
        public NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_1;
        public NDR64_MEMPAD_FORMAT frag2_2;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_3;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_4;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG47_EFSR
    {
        public NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
        public NDR64_ARRAY_ELEMENT_INFO frag2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG48_EFSR
    {
        public uint frag1;
        public NDR64_RANGE_FORMAT frag2;
        public NDR64_EXPR_VAR frag3;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG50_EFSR
    {
        public NDR64_POINTER_FORMAT frag1;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG52_EFSR
    {
        public NDR64_POINTER_FORMAT frag1;
        public NDR64_POINTER_FORMAT frag2;
        public NDR64_POINTER_FORMAT frag3;
    }

    // Equivalent to NDR64_POINTER_FORMAT
    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG53_EFSR
    {
        public byte FormatCode;
        public byte Flags;
        public ushort Reserved;
        public IntPtr Pointee;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG54_EFSR
    {
        public NDR64_POINTER_FORMAT frag1;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG56_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
        public NDR64_PARAM_FORMAT frag4;
        public NDR64_PARAM_FORMAT frag5;
    }

    // Equivalent to NDR64_POINTER_FORMAT
    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG59_EFSR
    {
        public byte FormatCode;
        public byte Flags;
        public ushort Reserved;
        public IntPtr Pointee;
    }

    // Equivalent to NDR64_POINTER_FORMAT
    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG60_EFSR
    {
        public byte FormatCode;
        public byte Flags;
        public ushort Reserved;
        public IntPtr Pointee;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG62_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
        public NDR64_PARAM_FORMAT frag4;
        public NDR64_PARAM_FORMAT frag5;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG67_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
        public NDR64_PARAM_FORMAT frag4;
        public NDR64_PARAM_FORMAT frag5;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG71_EFSR
    {
        public NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_1;
        public NDR64_MEMPAD_FORMAT frag2_2;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_3;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_4;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG72_EFSR
    {
        public NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
        public NDR64_REPEAT_FORMAT frag2_1;
        public NDR64_POINTER_INSTANCE_HEADER_FORMAT frag2_2_1;
        public NDR64_POINTER_FORMAT frag2_2_2;
        public byte frag2_3;
        public NDR64_ARRAY_ELEMENT_INFO frag3;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG9_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
        public NDR64_PARAM_FORMAT frag4;
        public NDR64_PARAM_FORMAT frag5;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG73_EFSR
    {
        public uint frag1;
        public NDR64_RANGE_FORMAT frag2;
        public NDR64_EXPR_VAR frag3;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG74_EFSR
    {
        public NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_1;
        public NDR64_MEMPAD_FORMAT frag2_2;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_3;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_4;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_5;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG75_EFSR
    {
        public NDR64_STRUCTURE_HEADER_FORMAT frag1;
        public NDR64_NO_REPEAT_FORMAT frag2_1;
        public NDR64_POINTER_INSTANCE_HEADER_FORMAT frag2_2;
        public NDR64_POINTER_FORMAT frag2_3;
        public byte frag2_4;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG76_EFSR
    {
        public NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
        public NDR64_ARRAY_ELEMENT_INFO frag2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG77_EFSR
    {
        public uint frag1;
        public NDR64_RANGE_FORMAT frag2;
        public NDR64_EXPR_VAR frag3;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG79_EFSR
    {
        public NDR64_POINTER_FORMAT frag1;
        public NDR64_POINTER_FORMAT frag2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG80_EFSR
    {
        public byte FormatCode;
        public byte Flags;
        public ushort Reserved;
        public IntPtr Pointee;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG81_EFSR
    {
        public NDR64_POINTER_FORMAT frag1;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG92_EFSR
    {
        public NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_1;
        public NDR64_MEMPAD_FORMAT frag2_2;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_3;
        public NDR64_SIMPLE_MEMBER_FORMAT frag2_4;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG93_EFSR
    {
        public NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
        public NDR64_ARRAY_ELEMENT_INFO frag2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG94_EFSR
    {
        public uint frag1;
        public NDR64_RANGE_FORMAT frag2;
        public NDR64_EXPR_VAR frag3;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG95_EFSR
    {
        public byte frag1;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG96_EFSR
    {
        public NDR64_POINTER_FORMAT frag1;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_FRAG99_EFSR
    {
        public NDR64_PROC_FORMAT frag1;
        public NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
        public NDR64_PARAM_FORMAT frag3;
        public NDR64_PARAM_FORMAT frag4;
        public NDR64_PARAM_FORMAT frag5;
        public NDR64_PARAM_FORMAT frag6;
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
    internal struct NDR64_CONF_STRUCTURE_HEADER_FORMAT
    {
        public byte FormatCode;
        public byte Alignment;
        public NDR64_STRUCTURE_FLAGS Flags;
        public byte Reserved;
        public uint ElementSize;
        public IntPtr ConfDescriptor;
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
    internal struct NDR64_NO_REPEAT_FORMAT
    {
        public byte FormatCode;
        public byte Flags;
        public ushort Reserved1;
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
    internal struct NDR64_POINTER_INSTANCE_HEADER_FORMAT
    {
        public uint Offset;
        public uint Reserved;
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
    internal struct NDR64_RANGE_FORMAT
    {
        public byte FormatCode;
        public byte RangeType;
        public ushort Reserved;
        public long MinValue;
        public long MaxValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NDR64_REPEAT_FORMAT
    {
        public byte FormatCode;
        public NDR64_POINTER_REPEAT_FLAGS Flags;
        public ushort Reserved;
        public uint Increment;
        public uint OffsetToArray;
        public uint NumberOfPointers;
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
    internal struct NDR64_STRUCTURE_HEADER_FORMAT
    {
        public byte FormatCode;
        public byte Alignment;
        public NDR64_STRUCTURE_FLAGS Flags;
        public byte Reserved;
        public uint MemorySize;
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
}
