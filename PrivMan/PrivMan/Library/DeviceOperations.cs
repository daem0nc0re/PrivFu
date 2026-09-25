using PrivMan.Interop;
using System;
using System.Runtime.InteropServices;

namespace PrivMan.Library
{
    using NTSTATUS = Int32;

    [StructLayout(LayoutKind.Sequential)]
    internal struct IOCTL_GET_TOKEN_PRIVILEGES_INPUT
    {
        public IntPtr UniqueProcess;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IOCTL_GET_TOKEN_PRIVILEGES_OUTPUT
    {
        public IntPtr UniqueProcess;
        public SEP_TOKEN_PRIVILEGES Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IOCTL_SET_TOKEN_PRIVILEGES_INPUT
    {
        public IntPtr UniqueProcess;
        public SEP_TOKEN_PRIVILEGES Privileges;
    }

    internal class DeviceOperations : IDisposable
    {
        private IntPtr g_DeviceHandle = IntPtr.Zero;
        private readonly uint IOCTL_GET_TOKEN_PRIVILEGES = 0x80000000;
        private readonly uint IOCTL_SET_TOKEN_PRIVILEGES = 0x80000004;

        //
        // Constructor and Destrcutor
        //
        internal DeviceOperations()
        {
            var deviceName = @"\??\PrivMan";
            var objectAttributes = new OBJECT_ATTRIBUTES(
                deviceName,
                OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive);
            NTSTATUS ntstatus = NativeMethods.NtCreateFile(
                out IntPtr hDevice,
                FileAccessFlags.GenericRead | FileAccessFlags.GenericWrite | FileAccessFlags.Synchronize,
                in objectAttributes,
                out IO_STATUS_BLOCK _,
                IntPtr.Zero,
                FILE_ATTRIBUTE_FLAGS.None,
                FILE_SHARE_ACCESS.None,
                FILE_CREATE_DISPOSITION.Open,
                FILE_CREATE_OPTIONS.NonDirectoryFile | FILE_CREATE_OPTIONS.SynchronousIoNonAlert,
                IntPtr.Zero,
                0u);
            objectAttributes.Dispose();

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                var nDosError = NativeMethods.RtlNtStatusToDosError(ntstatus);

                throw new Exception(string.Format("Failed to open \"{0}\" (Error = 0x{1}).",
                    deviceName,
                    nDosError.ToString("X8")));
            }
            else
            {
                g_DeviceHandle = hDevice;
            }
        }


        public void Dispose()
        {
            if (g_DeviceHandle != IntPtr.Zero)
            {
                NativeMethods.NtClose(g_DeviceHandle);
                g_DeviceHandle = IntPtr.Zero;
            }
        }


        //
        // IOCTL Operations
        //
        internal bool GetTokenPrivileges(
            int nProcessId,
            out IOCTL_GET_TOKEN_PRIVILEGES_OUTPUT data)
        {
            NTSTATUS ntstatus;
            var nInLength = (uint)Marshal.SizeOf(typeof(IOCTL_GET_TOKEN_PRIVILEGES_INPUT));
            var nOutLength = (uint)Marshal.SizeOf(typeof(IOCTL_GET_TOKEN_PRIVILEGES_OUTPUT));
            var input = new IOCTL_GET_TOKEN_PRIVILEGES_INPUT
            {
                UniqueProcess = new IntPtr(nProcessId)
            };
            var pInBuffer = Marshal.AllocHGlobal((int)nInLength);
            var pOutBuffer = Marshal.AllocHGlobal((int)nOutLength);
            Marshal.StructureToPtr(input, pInBuffer, true);

            ntstatus = NativeMethods.NtDeviceIoControlFile(
                g_DeviceHandle,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out IO_STATUS_BLOCK _,
                IOCTL_GET_TOKEN_PRIVILEGES,
                pInBuffer,
                nInLength,
                pOutBuffer,
                nOutLength);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                data = (IOCTL_GET_TOKEN_PRIVILEGES_OUTPUT)Marshal.PtrToStructure(
                    pOutBuffer,
                    typeof(IOCTL_GET_TOKEN_PRIVILEGES_OUTPUT));
            }
            else
            {
                var nDosError = NativeMethods.RtlNtStatusToDosError(ntstatus);
                NativeMethods.RtlSetLastWin32Error((int)nDosError);
                data = new IOCTL_GET_TOKEN_PRIVILEGES_OUTPUT();
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        internal bool SetTokenPrivileges(in IOCTL_SET_TOKEN_PRIVILEGES_INPUT privileges)
        {
            NTSTATUS ntstatus;
            var nInLength = (uint)Marshal.SizeOf(typeof(IOCTL_SET_TOKEN_PRIVILEGES_INPUT));
            var pInBuffer = Marshal.AllocHGlobal((int)nInLength);
            Marshal.StructureToPtr(privileges, pInBuffer, true);

            ntstatus = NativeMethods.NtDeviceIoControlFile(
                g_DeviceHandle,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out IO_STATUS_BLOCK _,
                IOCTL_SET_TOKEN_PRIVILEGES,
                pInBuffer,
                nInLength,
                IntPtr.Zero,
                0u);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                var nDosError = NativeMethods.RtlNtStatusToDosError(ntstatus);
                NativeMethods.RtlSetLastWin32Error((int)nDosError);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }
    }
}
