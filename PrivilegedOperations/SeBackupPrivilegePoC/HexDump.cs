using System;
using System.Text;
using System.Runtime.InteropServices;

namespace SeBackupPrivilegePoC
{
    internal class HexDump
    {
        public static void Dump(byte[] data, int nIndentCount)
        {
            IntPtr pBufferToRead = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, pBufferToRead, data.Length);

            Dump(pBufferToRead, new IntPtr(-1), (uint)data.Length, nIndentCount);

            Marshal.FreeHGlobal(pBufferToRead);
        }


        public static void Dump(byte[] data, uint nRange, int nIndentCount)
        {
            IntPtr pBufferToRead = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, pBufferToRead, data.Length);

            Dump(pBufferToRead, new IntPtr(-1), nRange, nIndentCount);

            Marshal.FreeHGlobal(pBufferToRead);
        }


        public static void Dump(byte[] data, IntPtr pBaseAddress, uint nRange, int nIndentCount)
        {
            IntPtr pBufferToRead = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, pBufferToRead, data.Length);

            Dump(pBufferToRead, pBaseAddress, nRange, nIndentCount);

            Marshal.FreeHGlobal(pBufferToRead);
        }


        public static void Dump(IntPtr pBufferToRead, uint nRange, int nIndentCount)
        {
            Dump(pBufferToRead, new IntPtr(-1), nRange, nIndentCount);
        }


        public static void Dump(IntPtr pBufferToRead, IntPtr pBaseAddress, uint nRange, int nIndentCount)
        {
            string addressFormat;
            string headFormat;
            string lineFormat;
            var hexBuilder = new StringBuilder();
            var charBuilder = new StringBuilder();
            var outputBuilder = new StringBuilder();

            if (pBaseAddress == new IntPtr(-1))
            {
                pBaseAddress = IntPtr.Zero;
                addressFormat = "X8";
                headFormat = string.Format("{{0,{0}}}   {{1,-47}}\n\n", 8 + (nIndentCount * 4));
                lineFormat = string.Format("{{0,{0}}} | {{1,-47}} | {{2}}\n", 8 + (nIndentCount * 4));
            }
            else
            {
                addressFormat = (IntPtr.Size == 8) ? "X16" : "X8";
                headFormat = string.Format("{{0,{0}}}   {{1,-47}}\n\n", (IntPtr.Size * 2) + (nIndentCount * 4));
                lineFormat = string.Format("{{0,{0}}} | {{1,-47}} | {{2}}\n", (IntPtr.Size * 2) + (nIndentCount * 4));
            }

            if (nRange > 0)
            {
                outputBuilder.AppendFormat(headFormat, string.Empty, "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");

                for (var idx = 0; idx < nRange; idx++)
                {
                    var address = pBaseAddress.ToInt64() + (idx & (~0x0Fu));
                    var readByte = Marshal.ReadByte(pBufferToRead, idx);
                    hexBuilder.Append(readByte.ToString("X2"));
                    charBuilder.Append(IsPrintable((char)readByte) ? (char)readByte : '.');

                    if ((idx % 16 == 15) || (idx == (nRange - 1)))
                    {
                        outputBuilder.AppendFormat(
                            lineFormat,
                            address.ToString(addressFormat),
                            hexBuilder.ToString(),
                            charBuilder.ToString());
                        hexBuilder.Clear();
                        charBuilder.Clear();
                    }
                    else if ((idx % 16 == 7) && (idx != (nRange - 1)))
                    {
                        hexBuilder.Append("-");
                        charBuilder.Append(" ");
                    }
                    else
                    {
                        hexBuilder.Append(" ");
                    }
                }

                Console.WriteLine(outputBuilder.ToString());
                outputBuilder.Clear();
            }
        }

        private static bool IsPrintable(char code)
        {
            return (Char.IsLetterOrDigit(code) || Char.IsPunctuation(code) || Char.IsSymbol(code));
        }
    }
}
