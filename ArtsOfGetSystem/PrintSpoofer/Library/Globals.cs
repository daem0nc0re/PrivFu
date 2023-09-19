using System;

namespace PrintSpoofer.Library
{
    internal class Globals
    {
        public static string PipeName { get; } = "PrivFuPipe";
        public static int Timeout { get; set; } = 3000;
    }
}
