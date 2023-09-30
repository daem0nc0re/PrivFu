using System;
using System.Runtime.InteropServices;

namespace RpcLibrary.Interop
{
    using SIZE_T = UIntPtr;

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void CS_TAG_GETTING_ROUTINE(
            IntPtr hBinding,
            int fServerSide,
            ref uint pulSendingTag,
            ref uint pulDesiredReceivingTag,
            ref uint pulReceivingTag,
            out uint pStatus);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void CS_TYPE_FROM_NETCS_ROUTINE(
        IntPtr hBinding,
        uint ulNetworkCodeSet,
        IntPtr pLocalData,
        uint ulLocalDataLength,
        byte[] pNetworkData,
        ref uint pulNetworkDataLength,
        out uint pStatus);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void CS_TYPE_LOCAL_SIZE_ROUTINE(
        IntPtr hBinding,
        uint ulNetworkCodeSet,
        uint ulNetworkBufferSize,
        in IDL_CS_CONVERT conversionType,
        ref uint pulLocalBufferSize,
        out uint pStatus);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void CS_TYPE_NET_SIZE_ROUTINE(
        IntPtr hBinding,
        uint ulNetworkCodeSet,
        uint ulLocalBufferSize,
        in IDL_CS_CONVERT conversionType,
        ref uint pulNetworkBufferSize,
        out uint pStatus);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void CS_TYPE_TO_NETCS_ROUTINE(
        IntPtr hBinding,
        uint ulNetworkCodeSet,
        IntPtr pLocalData,
        uint ulLocalDataLength,
        byte[] pNetworkData,
        ref uint pulNetworkDataLength,
        out uint pStatus);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void EXPR_EVAL(ref MIDL_STUB_MESSAGE midlStubMessage);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate IntPtr GENERIC_BINDING_ROUTINE(IntPtr Param0);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void GENERIC_UNBIND_ROUTINE(
        IntPtr Param0,
        IntPtr /* unsigned char* */ Param1);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate IntPtr MIDL_USER_ALLOCATE(SIZE_T size);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void MIDL_USER_FREE(IntPtr buffer);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void NDR_NOTIFY_ROUTINE();

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void NDR_RUNDOWN(IntPtr context);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void RPC_DISPATCH_FUNCTION(ref RPC_MESSAGE Message);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void USER_MARSHAL_FREEING_ROUTINE(
        ref uint Param0,
        IntPtr Param1);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate byte[] USER_MARSHAL_MARSHALLING_ROUTINE(
        ref uint Param0,
        byte[] Param1,
        IntPtr Param2);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint USER_MARSHAL_SIZING_ROUTINE(
        ref uint Param0,
        uint Param1,
        IntPtr Param2);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate byte[] USER_MARSHAL_UNMARSHALLING_ROUTINE(
        ref uint Param0,
        byte[] Param1,
        IntPtr Param2);
}
