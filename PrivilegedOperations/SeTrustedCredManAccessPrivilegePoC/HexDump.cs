using System;
using System.Text;
using System.Runtime.InteropServices;

namespace SeTrustedCredManAccessPrivilegePoC
{
    class HexDump
    {
        public static void Dump(byte[] data, int numIndent)
        {
            Dump(data, 0, data.Length, numIndent);
        }


        public static void Dump(byte[] data, int length, int numIndent)
        {
            if (length <= 0)
                return;

            Dump(data, 0, length, numIndent);
        }


        public static void Dump(IntPtr buffer, int length, int numIndent)
        {
            if (length <= 0)
                return;

            byte[] data = new byte[length];
            Marshal.Copy(buffer, data, 0, length);
            Dump(data, 0, length, numIndent);
        }


        public static void Dump(IntPtr buffer, int offset, int length, int numIndent)
        {
            if (length <= 0)
                return;

            byte[] data = new byte[length];
            Marshal.Copy(new IntPtr(buffer.ToInt64() + offset), data, 0, length);
            Dump(data, 0, length, numIndent);
        }


        public static void Dump(byte[] data, int offset, int length, int numIndent)
        {
            if (length <= 0)
                return;

            StringBuilder hexBuffer = new StringBuilder();
            StringBuilder charBuffer = new StringBuilder();
            string indent = new string('\t', numIndent);
            int address = 0;

            for (var idx = offset; idx < length; idx++)
            {
                if (idx % 16 == 0)
                {
                    address = idx & (~0xF);
                    hexBuffer.Clear();
                    charBuffer.Clear();
                }

                hexBuffer.Append(string.Format(
                    "{0}", data[idx].ToString("X2")));

                if (IsPrintable((char)data[idx]))
                {
                    charBuffer.Append((char)data[idx]);
                }
                else
                {
                    charBuffer.Append(".");
                }

                if ((idx + 1) % 8 == 0 &&
                    (idx + 1) % 16 != 0 &&
                    (idx + 1) != length)
                {
                    hexBuffer.Append("-");
                    charBuffer.Append(" ");
                }
                else if (((idx + 1) % 16 != 0) && ((idx + 1) != length))
                {
                    hexBuffer.Append(" ");
                }

                if ((idx + 1) % 16 == 0)
                {
                    Console.WriteLine("{0}{1} | {2} | {3}",
                        indent, address.ToString("X8"), hexBuffer, charBuffer);
                }
                else if ((idx + 1) == length)
                {
                    Console.WriteLine("{0}{1} | {2,-47} | {3}",
                        indent, address.ToString("X8"), hexBuffer, charBuffer);
                }
            }
        }

        private static bool IsPrintable(char code)
        {
            return Char.IsLetterOrDigit(code) ||
                        Char.IsPunctuation(code) ||
                        Char.IsSymbol(code);
        }
    }
}
