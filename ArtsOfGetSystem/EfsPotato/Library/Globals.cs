namespace EfsPotato.Library
{
    internal class Globals
    {
        public static string EndpointPipeName { get; set; } = null;
        public static string UserPipeName { get; set; } = null;
        public static int Timeout { get; set; } = 3000;
        public static RPC_PROC_OPTIONS RpcProcOpt { get; set; } = RPC_PROC_OPTIONS.EfsRpcEncryptFileSrv;
    }
}
