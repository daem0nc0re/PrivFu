using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using TrustExec.Interop;

namespace TrustExec.Library
{
    internal class ServiceQuery : IDisposable
    {
        private readonly IntPtr hSCObject = IntPtr.Zero;

        //
        // Expected Windows Error Codes
        //
        private const int ERROR_INSUFFICIENT_BUFFER = 0x7A;
        private const int ERROR_MORE_DATA = 0xEA;

        //
        // Constructor
        //
        public ServiceQuery()
        {
            this.hSCObject = NativeMethods.OpenSCManager(
                null,
                null,
                ACCESS_MASK.SC_MANAGER_ENUMERATE_SERVICE);

            if (hSCObject == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to open SCManager");
        }

        //
        // Destructor
        //
        public void Dispose()
        {
            NativeMethods.CloseServiceHandle(this.hSCObject);
        }

        //
        // Class Methods
        //
        public Dictionary<string, SERVICE_STATUS_PROCESS> EnumerateServiceConfig(
            SERVICE_TYPE dwServiceType,
            SERVICE_STATE dwServiceState,
            out Dictionary<string, string> displayNames)
        {
            bool bSuccess;
            IntPtr pInfoBuffer;
            int nInfoLength = 0x1000;
            var results = new Dictionary<string, SERVICE_STATUS_PROCESS>();
            displayNames = new Dictionary<string, string>();

            do
            {
                int nResumeIndex = 0;
                pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
                bSuccess = NativeMethods.EnumServicesStatusExW(
                    this.hSCObject,
                    SC_ENUM_TYPE.PROCESS_INFO,
                    dwServiceType,
                    dwServiceState,
                    pInfoBuffer,
                    nInfoLength,
                    out int nRequiredBytes,
                    out int nReturnedBytes,
                    ref nResumeIndex,
                    null);

                if (!bSuccess)
                {
                    Marshal.FreeHGlobal(pInfoBuffer);
                    nInfoLength += nRequiredBytes;
                }
                else
                {
                    nInfoLength = nReturnedBytes;
                }
            } while (!bSuccess && (Marshal.GetLastWin32Error() == ERROR_MORE_DATA));

            if (bSuccess)
            {
                IntPtr pDataBuffer = pInfoBuffer;
                int nUnitSize = Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS_PROCESSW));

                while (Marshal.ReadIntPtr(pDataBuffer) != IntPtr.Zero)
                {
                    var info = (ENUM_SERVICE_STATUS_PROCESSW)Marshal.PtrToStructure(
                        pDataBuffer,
                        typeof(ENUM_SERVICE_STATUS_PROCESSW));
                    results.Add(info.lpServiceName, info.ServiceStatusProcess);
                    displayNames.Add(info.lpServiceName, info.lpDisplayName);

                    if (Environment.Is64BitProcess)
                        pDataBuffer = new IntPtr(pDataBuffer.ToInt64() + nUnitSize);
                    else
                        pDataBuffer = new IntPtr(pDataBuffer.ToInt32() + nUnitSize);
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return results;
        }


        public IntPtr GetSecurityDescriptor(string serviceName)
        {
            IntPtr pSecurityDescriptor;
            bool bSuccess;
            int nInfoLength = 0x200;
            IntPtr hService = NativeMethods.OpenService(
                this.hSCObject,
                serviceName,
                ACCESS_MASK.READ_CONTROL);

            if (hService == IntPtr.Zero)
                return IntPtr.Zero;

            do
            {
                pSecurityDescriptor = Marshal.AllocHGlobal(nInfoLength);
                bSuccess = NativeMethods.QueryServiceObjectSecurity(
                    hService,
                    SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION | SECURITY_INFORMATION.DACL_SECURITY_INFORMATION,
                    pSecurityDescriptor,
                    nInfoLength,
                    out nInfoLength);

                if (!bSuccess)
                {
                    Marshal.FreeHGlobal(pSecurityDescriptor);
                    pSecurityDescriptor = IntPtr.Zero;
                }
            } while (!bSuccess && (Marshal.GetLastWin32Error() == ERROR_INSUFFICIENT_BUFFER));

            NativeMethods.CloseServiceHandle(hService);

            return pSecurityDescriptor;
        }


        public string GetServiceBinaryPath(string serviceName)
        {
            bool bSuccess;
            IntPtr pInfoBuffer;
            int nInfoLength = 0x1000;
            string binaryPathName = null;
            IntPtr hService = NativeMethods.OpenService(
                this.hSCObject,
                serviceName,
                ACCESS_MASK.SERVICE_QUERY_CONFIG);

            if (hService == IntPtr.Zero)
                return null;

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
                bSuccess = NativeMethods.QueryServiceConfigW(
                    hService,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (!bSuccess)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (!bSuccess && (Marshal.GetLastWin32Error() == ERROR_INSUFFICIENT_BUFFER));

            if (bSuccess)
            {
                var info = (QUERY_SERVICE_CONFIGW)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(QUERY_SERVICE_CONFIGW));
                binaryPathName = string.IsNullOrEmpty(info.lpBinaryPathName) ? null : info.lpBinaryPathName;
                Marshal.FreeHGlobal(pInfoBuffer);
            }

            NativeMethods.CloseServiceHandle(hService);

            return binaryPathName;
        }


        // Returns PQUERY_SERVICE_CONFIGW
        public IntPtr GetServiceConfiguration(string serviceName)
        {
            bool bSuccess;
            IntPtr pInfoBuffer;
            int nInfoLength = 0x1000;
            IntPtr hService = NativeMethods.OpenService(
                this.hSCObject,
                serviceName,
                ACCESS_MASK.SERVICE_QUERY_CONFIG);

            if (hService == IntPtr.Zero)
                return IntPtr.Zero;

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
                bSuccess = NativeMethods.QueryServiceConfigW(
                    hService,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (!bSuccess)
                {
                    Marshal.FreeHGlobal(pInfoBuffer);
                    pInfoBuffer = IntPtr.Zero;
                }
            } while (!bSuccess && (Marshal.GetLastWin32Error() == ERROR_INSUFFICIENT_BUFFER));

            NativeMethods.CloseServiceHandle(hService);

            return pInfoBuffer;
        }


        // Returns PSERVICE_STATUS_PROCESS
        public IntPtr GetServiceStatus(string serviceName)
        {
            bool bSuccess;
            IntPtr pInfoBuffer;
            int nDosErrorCode;
            int nInfoLength = 0x1000;
            IntPtr hService = NativeMethods.OpenService(
                this.hSCObject,
                serviceName,
                ACCESS_MASK.SERVICE_QUERY_STATUS);

            if (hService == IntPtr.Zero)
                return IntPtr.Zero;

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
                bSuccess = NativeMethods.QueryServiceStatusEx(
                    hService,
                    SC_STATUS_TYPE.PROCESS_INFO,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);
                nDosErrorCode = Marshal.GetLastWin32Error();

                if (!bSuccess)
                {
                    Marshal.FreeHGlobal(pInfoBuffer);
                    pInfoBuffer = IntPtr.Zero;
                }
            } while (!bSuccess && (nDosErrorCode == ERROR_INSUFFICIENT_BUFFER));

            NativeMethods.CloseServiceHandle(hService);

            return pInfoBuffer;
        }


        public bool StartService(string serviceName)
        {
            bool bSuccess;
            IntPtr hService = NativeMethods.OpenService(
                this.hSCObject,
                serviceName,
                ACCESS_MASK.SERVICE_START);

            if (hService == IntPtr.Zero)
                return false;

            bSuccess = NativeMethods.StartServiceW(hService, 0, new string[] { });

            if (bSuccess)
            {
                var state = SERVICE_CURRENT_STATE.STOPPED;
                var nStateOffset = Marshal.OffsetOf(typeof(SERVICE_STATUS_PROCESS), "dwCurrentState").ToInt32();

                while (state != SERVICE_CURRENT_STATE.RUNNING)
                {
                    IntPtr pInfoBuffer = GetServiceStatus(serviceName);

                    if (pInfoBuffer != IntPtr.Zero)
                    {
                        state = (SERVICE_CURRENT_STATE)Marshal.ReadInt32(pInfoBuffer, nStateOffset);
                        Marshal.FreeHGlobal(pInfoBuffer);
                    }
                    else
                    {
                        break;
                    }
                }
            }

            NativeMethods.CloseServiceHandle(hService);

            return bSuccess;
        }


        public bool StopService(string serviceName)
        {
            var bSuccess = false;
            IntPtr hService = NativeMethods.OpenService(
                this.hSCObject,
                serviceName,
                ACCESS_MASK.SERVICE_STOP);

            if (hService != IntPtr.Zero)
            {
                bSuccess = NativeMethods.ControlService(hService, SERVICE_CONTROL.STOP, out SERVICE_STATUS _);
                NativeMethods.CloseServiceHandle(hService);
            }

            return bSuccess;
        }
    }
}
