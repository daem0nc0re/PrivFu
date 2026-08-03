namespace SystemServiceExec.Library
{
    internal class Globals
    {
        public static string ServiceName { get; } = "SystemServiceExecSvc";
        public static bool IsServiceCreated { get; set; } = false;
        public static bool IsServiceDeleted { get; set; } = false;
    }
}
