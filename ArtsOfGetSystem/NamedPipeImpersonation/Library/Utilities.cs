using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using TaskScheduler;
using NamedPipeImpersonation.Interop;

namespace NamedPipeImpersonation.Library
{
    internal class Utilities
    {
        internal static bool CreateSystemExecTask(
            string taskname,
            string binpath,
            string args,
            out Exception exception)
        {
            var bSuccess = false;
            exception = null;

            unsafe
            {
                try
                {
                    ITaskDefinition definition;
                    IExecAction action;
                    ITaskFolder folder;
                    IRegisteredTask task;
                    var scheduler = new TaskScheduler.TaskScheduler();
                    scheduler.Connect();

                    definition = scheduler.NewTask(0);
                    definition.RegistrationInfo.Description = taskname;
                    definition.Principal.UserId = "SYSTEM";
                    definition.Principal.RunLevel = _TASK_RUNLEVEL.TASK_RUNLEVEL_HIGHEST;
                    definition.Settings.AllowDemandStart = true;
                    definition.Settings.DisallowStartIfOnBatteries = false;

                    action = (IExecAction)definition.Actions.Create(_TASK_ACTION_TYPE.TASK_ACTION_EXEC);
                    action.Path = binpath;
                    action.Arguments = args;

                    folder = scheduler.GetFolder("\\");
                    task = folder.RegisterTaskDefinition(
                        taskname,
                        definition,
                        (int)_TASK_CREATION.TASK_CREATE_OR_UPDATE,
                        null,
                        null,
                        _TASK_LOGON_TYPE.TASK_LOGON_SERVICE_ACCOUNT);
                    task.Run(null);
                    folder.DeleteTask(taskname, 0);
                    bSuccess = true;
                }
                catch (Exception ex)
                {
                    exception = ex;
                }
            }

            return bSuccess;
        }


        public static bool EnableTokenPrivileges(
            List<string> requiredPrivs,
            out Dictionary<string, bool> adjustedPrivs)
        {
            return EnableTokenPrivileges(
                WindowsIdentity.GetCurrent().Token,
                requiredPrivs,
                out adjustedPrivs);
        }


        public static bool EnableTokenPrivileges(
            IntPtr hToken,
            List<string> requiredPrivs,
            out Dictionary<string, bool> adjustedPrivs)
        {
            var allEnabled = true;
            adjustedPrivs = new Dictionary<string, bool>();

            do
            {
                if (requiredPrivs.Count == 0)
                    break;

                allEnabled = Helpers.GetTokenPrivileges(
                    hToken,
                    out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                if (!allEnabled)
                    break;

                foreach (var priv in requiredPrivs)
                {
                    adjustedPrivs.Add(priv, false);

                    foreach (var available in availablePrivs)
                    {
                        if (string.Compare(available.Key, priv, true) == 0)
                        {
                            if ((available.Value & SE_PRIVILEGE_ATTRIBUTES.Enabled) != 0)
                            {
                                adjustedPrivs[priv] = true;
                            }
                            else
                            {
                                var tokenPrivileges = new TOKEN_PRIVILEGES
                                {
                                    PrivilegeCount = 1,
                                    Privileges = new LUID_AND_ATTRIBUTES[1]
                                };

                                if (NativeMethods.LookupPrivilegeValue(
                                    null,
                                    priv,
                                    out tokenPrivileges.Privileges[0].Luid))
                                {
                                    var nInfoLength = Marshal.SizeOf(typeof(TOKEN_PRIVILEGES));
                                    var pTokenPrivileges = Marshal.AllocHGlobal(nInfoLength);
                                    tokenPrivileges.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.Enabled;
                                    Marshal.StructureToPtr(tokenPrivileges, pTokenPrivileges, true);

                                    adjustedPrivs[priv] = NativeMethods.AdjustTokenPrivileges(
                                        hToken,
                                        false,
                                        pTokenPrivileges,
                                        nInfoLength,
                                        IntPtr.Zero,
                                        out int _);
                                    adjustedPrivs[priv] &= (Marshal.GetLastWin32Error() == 0);
                                    Marshal.FreeHGlobal(pTokenPrivileges);
                                }
                            }

                            break;
                        }
                    }

                    if (!adjustedPrivs[priv])
                        allEnabled = false;
                }
            } while (false);

            return allEnabled;
        }


        public static IntPtr StartNamedPipeClientService(string binpath)
        {
            var hService = IntPtr.Zero;
            IntPtr hSCManager = NativeMethods.OpenSCManager(
                null,
                null,
                ACCESS_MASK.SC_MANAGER_CONNECT | ACCESS_MASK.SC_MANAGER_CREATE_SERVICE);

            if (hSCManager != IntPtr.Zero)
            {
                hService = NativeMethods.CreateService(
                    hSCManager,
                    Globals.ServiceName,
                    Globals.ServiceName,
                    ACCESS_MASK.SERVICE_ALL_ACCESS,
                    SERVICE_TYPE.Win32OwnProcess,
                    START_TYPE.Demand,
                    ERROR_CONTROL.Normal,
                    binpath,
                    null,
                    IntPtr.Zero,
                    null,
                    null,
                    null);
                NativeMethods.CloseServiceHandle(hSCManager);

                if (hService != IntPtr.Zero)
                    NativeMethods.StartService(hService, 0, IntPtr.Zero);
            }

            return hService;
        }
    }
}
