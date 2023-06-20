using System;
using System.IO.Pipes;
using System.Text;

namespace NamedPipeClient
{
    internal class NamedPipeClient
    {
        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                try
                {
                    using (var pipeClient = new NamedPipeClientStream(".", args[0], PipeDirection.Out))
                    {
                        var message = Encoding.ASCII.GetBytes(args[0]);
                        pipeClient.Connect(3000);
                        pipeClient.Write(message, 0, message.Length);
                    }
                }
                catch { }
            }
        }
    }
}
