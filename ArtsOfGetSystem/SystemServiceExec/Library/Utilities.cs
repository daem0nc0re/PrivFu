using System;
using System.Threading;
using SystemServiceExec.Interop;

namespace SystemServiceExec.Library
{
    internal class Utilities
    {
        internal static bool CreateProcessAsSystemService(
            string serviceName,
            string displayName,
            string binpath,
            int nDelayMilliseconds)
        {
            var bSuccess = false;
            IntPtr hManager = NativeMethods.OpenSCManagerW(
                null,
                null,
                ACCESS_MASK.SCManagerConnect | ACCESS_MASK.SCManagerCreateService);

            if (hManager == IntPtr.Zero)
                return false;

            IntPtr hService = NativeMethods.CreateService(
                hManager,
                serviceName,
                displayName,
                ACCESS_MASK.GenericAll,
                SERVICE_TYPE.Win32OwnProcess,
                START_TYPE.DemandStart,
                ERROR_CONTROL.Ignore,
                binpath,
                null,
                IntPtr.Zero,
                null,
                null,
                null);

            if (hService != IntPtr.Zero)
            {
                NativeMethods.StartServiceW(hService, 0, null);
                Thread.Sleep(nDelayMilliseconds);
                NativeMethods.DeleteService(hService);
                NativeMethods.CloseServiceHandle(hService);
                bSuccess = true;
            }

            NativeMethods.CloseServiceHandle(hManager);

            return bSuccess;
        }
    }
}
