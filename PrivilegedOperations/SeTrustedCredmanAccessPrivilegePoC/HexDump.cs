using System;
using System.Text;
using System.Runtime.InteropServices;

namespace SeTrustedCredManAccessPrivilegePoC
{
    class HexDump
    {
        public static void Dump(IntPtr lpBuffer, int bufferSize, int numIndent)
        {
            if (bufferSize <= 0)
                return;

            StringBuilder hexBuffer = new StringBuilder();
            StringBuilder charBuffer = new StringBuilder();
            string indent = new string('\t', numIndent);
            byte[] byteArray = new byte[bufferSize];
            int address = 0;

            Marshal.Copy(lpBuffer, byteArray, 0, bufferSize);

            for (var idx = 0; idx < bufferSize; idx++)
            {
                if (idx % 16 == 0)
                {
                    address = (idx / 16) * 16;
                    hexBuffer.Clear();
                    charBuffer.Clear();
                }

                hexBuffer.Append(string.Format(
                    "{0}", byteArray[idx].ToString("X2")));

                if (IsPrintable((char)byteArray[idx]))
                {
                    charBuffer.Append((char)byteArray[idx]);
                }
                else
                {
                    charBuffer.Append(".");
                }

                if ((idx + 1) % 8 == 0 &&
                    (idx + 1) % 16 != 0 &&
                    (idx + 1) != bufferSize)
                {
                    hexBuffer.Append("-");
                    charBuffer.Append(" ");
                }
                else if (((idx + 1) % 16 != 0) && ((idx + 1) != bufferSize))
                {
                    hexBuffer.Append(" ");
                }

                if ((idx + 1) % 16 == 0)
                {
                    Console.WriteLine("{0}{1} | {2} | {3}",
                        indent, address.ToString("X8"), hexBuffer, charBuffer);
                }
                else if ((idx + 1) == bufferSize)
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
