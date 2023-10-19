using System;
using System.Runtime.InteropServices;
using RpcLibrary;

namespace RpcLibrary.Interop
{
    using RPC_STATUS = Int32;

    internal class NativeMethods
    {
        /*
         * rpcrt4.dll
         */
        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr NdrClientCall3(
            IntPtr /* in MIDL_STUBLESS_PROXY_INFO */ pProxyInfo,
            uint nProcNum,
            IntPtr pReturnValue,
            IntPtr hContext);


        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr NdrClientCall3(
            IntPtr /* in MIDL_STUBLESS_PROXY_INFO */ pProxyInfo,
            uint nProcNum,
            IntPtr pReturnValue,
            IntPtr hBinding,
            string FileName);

        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr NdrClientCall3(
            IntPtr /* in MIDL_STUBLESS_PROXY_INFO */ pProxyInfo,
            uint nProcNum,
            IntPtr pReturnValue,
            IntPtr hBinding,
            out IntPtr hContext,
            string FileName,
            int Flags);

        [DllImport("rpcrt4.dll")]
        public static extern RPC_STATUS RpcBindingFree(ref IntPtr Binding);

        [DllImport("rpcrt4.dll", EntryPoint = "RpcBindingFromStringBindingW", CharSet = CharSet.Unicode)]
        public static extern RPC_STATUS RpcBindingFromStringBinding(
            IntPtr StringBinding,
            out IntPtr Binding);

        [DllImport("rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoW", CharSet = CharSet.Unicode)]
        public static extern RPC_STATUS RpcBindingSetAuthInfo(
            IntPtr Binding,
            string ServerPrincName,
            RPC_C_AUTHN_LEVEL AuthnLevel,
            RPC_C_AUTHN AuthnSvc,
            IntPtr AuthIdentity,
            RPC_C_AUTHZ AuthzSvc);

        [DllImport("rpcrt4.dll")]
        public static extern RPC_STATUS RpcBindingSetOption(
            IntPtr hBinding,
            RPC_C_OPT option,
            UIntPtr optionValue);

        [DllImport("rpcrt4.dll")]
        public static extern RPC_STATUS RpcEpResolveBinding(IntPtr Binding, IntPtr IfSpec);

        [DllImport("rpcrt4.dll")]
        public static extern RPC_STATUS RpcIfIdVectorFree(in IntPtr /* RPC_IF_ID_VECTOR** */ IfIdVector);

        [DllImport("rpcrt4.dll")]
        public static extern RPC_STATUS RpcMgmtInqIfIds(
            IntPtr Binding,
            out IntPtr /* RPC_IF_ID_VECTOR** */ IfIdVector);

        [DllImport("rpcrt4.dll", EntryPoint = "RpcStringBindingComposeW", CharSet = CharSet.Unicode)]
        public static extern RPC_STATUS RpcStringBindingCompose(
            string ObjUuid,
            string ProtSeq,
            string NetworkAddr,
            string Endpoint,
            string Options,
            out IntPtr /* wchar_t** */ StringBinding);

        [DllImport("rpcrt4.dll", EntryPoint = "RpcStringFreeW", CharSet = CharSet.Unicode)]
        public static extern RPC_STATUS RpcStringFree(in IntPtr /* wchar_t** */ RpcString);
    }
}
