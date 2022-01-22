using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using SwitchPriv.Interop;

namespace SwitchPriv.Library
{
    class Utilities
    {
        public static bool DisableSinglePrivilege(IntPtr hToken, Win32Struct.LUID priv)
        {
            int error;

            Win32Struct.TOKEN_PRIVILEGES tp = new Win32Struct.TOKEN_PRIVILEGES(1);
            tp.Privilege[0].Luid = priv;
            tp.Privilege[0].Attributes = 0;

            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(tp));
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            if (!Win32Api.AdjustTokenPrivileges(
                hToken,
                false,
                pTokenPrivilege,
                0,
                IntPtr.Zero,
                IntPtr.Zero))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to disable {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            error = Marshal.GetLastWin32Error();

            if (error != 0)
            {
                Console.WriteLine("[-] Failed to disable {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                return false;
            }

            return true;
        }


        public static bool EnableSinglePrivilege(IntPtr hToken, Win32Struct.LUID priv)
        {
            int error;

            Win32Struct.TOKEN_PRIVILEGES tp = new Win32Struct.TOKEN_PRIVILEGES(1);
            tp.Privilege[0].Luid = priv;
            tp.Privilege[0].Attributes = (uint)Win32Const.PrivilegeAttributeFlags.SE_PRIVILEGE_ENABLED;

            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(tp));
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            if (!Win32Api.AdjustTokenPrivileges(
                hToken,
                false,
                pTokenPrivilege,
                0,
                IntPtr.Zero,
                IntPtr.Zero))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to enable {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            error = Marshal.GetLastWin32Error();

            if (error != 0)
            {
                Console.WriteLine("[-] Failed to enable {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                return false;
            }

            return true;
        }


        public static Dictionary<Win32Struct.LUID, uint> GetAvailablePrivileges(IntPtr hToken)
        {
            int ERROR_INSUFFICIENT_BUFFER = 122;
            int error;
            bool status;
            int bufferLength = Marshal.SizeOf(typeof(Win32Struct.TOKEN_PRIVILEGES));
            Dictionary<Win32Struct.LUID, uint> availablePrivs = new Dictionary<Win32Struct.LUID, uint>();
            IntPtr pTokenPrivileges;

            do
            {
                pTokenPrivileges = Marshal.AllocHGlobal(bufferLength);
                Helpers.ZeroMemory(pTokenPrivileges, bufferLength);

                status = Win32Api.GetTokenInformation(
                    hToken,
                    Win32Const.TOKEN_INFORMATION_CLASS.TokenPrivileges,
                    pTokenPrivileges,
                    bufferLength,
                    out bufferLength);
                error = Marshal.GetLastWin32Error();

                if (!status)
                    Marshal.FreeHGlobal(pTokenPrivileges);
            } while (!status && (error == ERROR_INSUFFICIENT_BUFFER));

            if (!status)
                return availablePrivs;

            int privCount = Marshal.ReadInt32(pTokenPrivileges);
            IntPtr buffer = new IntPtr(pTokenPrivileges.ToInt64() + Marshal.SizeOf(privCount));

            for (var count = 0; count < privCount; count++)
            {
                var luidAndAttr = (Win32Struct.LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                    buffer,
                    typeof(Win32Struct.LUID_AND_ATTRIBUTES));

                availablePrivs.Add(luidAndAttr.Luid, luidAndAttr.Attributes);
                buffer = new IntPtr(buffer.ToInt64() + Marshal.SizeOf(luidAndAttr));
            }

            Marshal.FreeHGlobal(pTokenPrivileges);

            return availablePrivs;
        }


        public static int GetParentProcessId(IntPtr hProcess)
        {
            var sizeInformation = Marshal.SizeOf(typeof(Win32Struct.PROCESS_BASIC_INFORMATION));
            var buffer = Marshal.AllocHGlobal(sizeInformation);

            if (hProcess == IntPtr.Zero)
                return 0;

            int ntstatus = Win32Api.NtQueryInformationProcess(
                hProcess,
                Win32Const.PROCESSINFOCLASS.ProcessBasicInformation,
                buffer,
                sizeInformation,
                IntPtr.Zero);

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to get process information.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(ntstatus, true));
                Marshal.FreeHGlobal(buffer);
                return 0;
            }

            var basicInfo = (Win32Struct.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(
                buffer,
                typeof(Win32Struct.PROCESS_BASIC_INFORMATION));
            int ppid = basicInfo.InheritedFromUniqueProcessId.ToInt32();

            Marshal.FreeHGlobal(buffer);

            return ppid;
        }
    }
}
