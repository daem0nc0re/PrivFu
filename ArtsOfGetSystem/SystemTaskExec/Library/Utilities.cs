using System;
using TaskScheduler;

namespace SystemTaskExec.Library
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

            return bSuccess;
        }
    }
}
