using System;
using System.Runtime.InteropServices;

namespace SeLockMemoryPrivilegePoC
{
    using SIZE_T = UIntPtr;

    internal class SeLockMemoryPrivilegePoC
    {
        /*
         * P/Invoke : Enums
         */
        [Flags]
        private enum MEMORY_ALLOCATION_FLAGS : uint
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000,
            MEM_DECOMMIT = 0x00004000,
            MEM_RELEASE = 0x00008000,
            MEM_RESET = 0x00080000,
            MEM_TOP_DOWN = 0x00100000,
            MEM_WRITE_WATCH = 0x00200000,
            MEM_PHYSICAL = 0x00400000,
            MEM_RESET_UNDO = 0x10000000,
            MEM_LARGE_PAGES = 0x20000000
        }

        [Flags]
        private enum MEMORY_PROTECTION_FLAGS : uint
        {
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }


        /*
         * P/Invoke : Win32 APIs
         */
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SIZE_T GetLargePageMinimum();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFree(
            IntPtr lpAddress,
            SIZE_T dwSize,
            MEMORY_ALLOCATION_FLAGS dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            SIZE_T dwSize,
            MEMORY_ALLOCATION_FLAGS flAllocationType,
            MEMORY_PROTECTION_FLAGS flProtect);

        /*
         * Global Variables
         */
        private static IntPtr LargePagePointer = IntPtr.Zero;


        static void Main()
        {
            Console.WriteLine("[*] If you have SeLockMemoryPrivilege, you can consume physical memory with Lage Pages or AWE.");
            Console.WriteLine("[*] This PoC tries to allocate 1 Large page.");

            bool bSuccess;
            SIZE_T nLargePageUnit = GetLargePageMinimum();

            if (nLargePageUnit == SIZE_T.Zero)
            {
                Console.WriteLine("[-] Large Page may not be supported (Error = 0x{0}).",
                    Marshal.GetLastWin32Error().ToString("X8"));
                return;
            }
            else
            {
                if (Environment.Is64BitProcess)
                {
                    Console.WriteLine("[*] Large Page unit size is 0x{0}.",
                        nLargePageUnit.ToUInt64().ToString("X16"));
                }
                else
                {
                    Console.WriteLine("[*] Large Page unit size is 0x{0}.",
                        nLargePageUnit.ToUInt64().ToString("X8"));
                }
            }

            LargePagePointer = VirtualAlloc(
                IntPtr.Zero,
                nLargePageUnit,
                MEMORY_ALLOCATION_FLAGS.MEM_COMMIT | MEMORY_ALLOCATION_FLAGS.MEM_RESERVE | MEMORY_ALLOCATION_FLAGS.MEM_LARGE_PAGES,
                MEMORY_PROTECTION_FLAGS.PAGE_READWRITE);

            if (LargePagePointer == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to allocate large pages (Error = 0x{0}).",
                    Marshal.GetLastWin32Error().ToString("X8"));
                return;
            }
            else
            {
                Console.WriteLine("[+] Large pages are allocated at 0x{0} successfully.",
                    LargePagePointer.ToString(Environment.Is64BitProcess ? "X16" : "X8"));
                Console.WriteLine("[DEBUG BREAK]");
                Console.ReadLine();
            }

            bSuccess = VirtualFree(LargePagePointer, SIZE_T.Zero, MEMORY_ALLOCATION_FLAGS.MEM_RELEASE);

            if (!bSuccess)
            {
                Console.WriteLine("[-] Failed to release large pages (Error = 0x{0}).",
                    Marshal.GetLastWin32Error().ToString("X8"));
            }
            else
            {
                Console.WriteLine("[+] Large pages are released successfully.");
            }
        }
    }
}
