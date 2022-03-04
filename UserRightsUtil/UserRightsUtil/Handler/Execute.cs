using System;
using UserRightsUtil.Interop;
using UserRightsUtil.Library;

namespace UserRightsUtil.Handler
{
    class Execute
    {
        // Helpers
        static void ListRights()
        {
            Console.WriteLine("\t+ TrustedCredManAccess           : Specfies SeTrustedCredManAccessPrivilege.");
            Console.WriteLine("\t+ NetworkLogon                   : Specfies SeNetworkLogonRight.");
            Console.WriteLine("\t+ Tcb                            : Specfies SeTcbPrivilege.");
            Console.WriteLine("\t+ MachineAccount                 : Specfies SeMachineAccountPrivilege.");
            Console.WriteLine("\t+ IncreaseQuota                  : Specfies SeIncreaseQuotaPrivilege.");
            Console.WriteLine("\t+ InteractiveLogon               : Specfies SeInteractiveLogonRight.");
            Console.WriteLine("\t+ RemoteInteractiveLogon         : Specfies SeRemoteInteractiveLogonRight.");
            Console.WriteLine("\t+ Backup                         : Specfies SeBackupPrivilege.");
            Console.WriteLine("\t+ ChangeNotify                   : Specfies SeChangeNotifyPrivilege.");
            Console.WriteLine("\t+ Systemtime                     : Specfies SeSystemtimePrivilege.");
            Console.WriteLine("\t+ TimeZone                       : Specfies SeTimeZonePrivilege.");
            Console.WriteLine("\t+ CreatePagefile                 : Specfies SeCreatePagefilePrivilege.");
            Console.WriteLine("\t+ CreateToken                    : Specfies SeCreateTokenPrivilege.");
            Console.WriteLine("\t+ CreateGlobal                   : Specfies SeCreateGlobalPrivilege.");
            Console.WriteLine("\t+ CreatePermanent                : Specfies SeCreatePermanentPrivilege.");
            Console.WriteLine("\t+ CreateSymbolicLink             : Specfies SeCreateSymbolicLinkPrivilege.");
            Console.WriteLine("\t+ Debug                          : Specfies SeDebugPrivilege.");
            Console.WriteLine("\t+ DenyNetworkLogon               : Specfies SeDenyNetworkLogonRight.");
            Console.WriteLine("\t+ DenyBatchLogon                 : Specfies SeDenyBatchLogonRight.");
            Console.WriteLine("\t+ DenyServiceLogon               : Specfies SeDenyServiceLogonRight.");
            Console.WriteLine("\t+ DenyInteractiveLogon           : Specfies SeDenyInteractiveLogonRight.");
            Console.WriteLine("\t+ DenyRemoteInteractiveLogon     : Specfies SeDenyRemoteInteractiveLogonRight.");
            Console.WriteLine("\t+ EnableDelegation               : Specfies SeEnableDelegationPrivilege.");
            Console.WriteLine("\t+ RemoteShutdown                 : Specfies SeRemoteShutdownPrivilege.");
            Console.WriteLine("\t+ Audit                          : Specfies SeAuditPrivilege.");
            Console.WriteLine("\t+ Impersonate                    : Specfies SeImpersonatePrivilege.");
            Console.WriteLine("\t+ IncreaseWorkingSet             : Specfies SeIncreaseWorkingSetPrivilege.");
            Console.WriteLine("\t+ IncreaseBasePriority           : Specfies SeIncreaseBasePriorityPrivilege.");
            Console.WriteLine("\t+ LoadDriver                     : Specfies SeLoadDriverPrivilege.");
            Console.WriteLine("\t+ LockMemory                     : Specfies SeLockMemoryPrivilege.");
            Console.WriteLine("\t+ BatchLogon                     : Specfies SeBatchLogonRight.");
            Console.WriteLine("\t+ ServiceLogon                   : Specfies SeServiceLogonRight.");
            Console.WriteLine("\t+ Security                       : Specfies SeSecurityPrivilege.");
            Console.WriteLine("\t+ Relabel                        : Specfies SeRelabelPrivilege.");
            Console.WriteLine("\t+ SystemEnvironment              : Specfies SeSystemEnvironmentPrivilege.");
            Console.WriteLine("\t+ DelegateSessionUserImpersonate : Specfies SeDelegateSessionUserImpersonatePrivilege.");
            Console.WriteLine("\t+ ManageVolume                   : Specfies SeManageVolumePrivilege.");
            Console.WriteLine("\t+ ProfileSingleProcess           : Specfies SeProfileSingleProcessPrivilege.");
            Console.WriteLine("\t+ SystemProfile                  : Specfies SeSystemProfilePrivilege.");
            Console.WriteLine("\t+ UnsolicitedInput               : Specfies SeUnsolicitedInputPrivilege.");
            Console.WriteLine("\t+ Undock                         : Specfies SeUndockPrivilege.");
            Console.WriteLine("\t+ AssignPrimaryToken             : Specfies SeAssignPrimaryTokenPrivilege.");
            Console.WriteLine("\t+ Restore                        : Specfies SeRestorePrivilege.");
            Console.WriteLine("\t+ Shutdown                       : Specfies SeShutdownPrivilege.");
            Console.WriteLine("\t+ SyncAgent                      : Specfies SeSyncAgentPrivilege.");
            Console.WriteLine("\t+ TakeOwnership                  : Specfies SeTakeOwnershipPrivilege.");
        }


        static bool ResolveRights(string right, out Win32Const.Rights userRight)
        {
            var opt = StringComparison.OrdinalIgnoreCase;
            userRight = Win32Const.Rights.SeTrustedCredManAccessPrivilege;

            if (string.Compare(right, "TrustedCredManAccess", opt) == 0)
                userRight = Win32Const.Rights.SeTrustedCredManAccessPrivilege;
            else if (string.Compare(right, "NetworkLogon", opt) == 0)
                userRight = Win32Const.Rights.SeNetworkLogonRight;
            else if (string.Compare(right, "Tcb", opt) == 0)
                userRight = Win32Const.Rights.SeTcbPrivilege;
            else if (string.Compare(right, "MachineAccount", opt) == 0)
                userRight = Win32Const.Rights.SeMachineAccountPrivilege;
            else if (string.Compare(right, "IncreaseQuota", opt) == 0)
                userRight = Win32Const.Rights.SeIncreaseQuotaPrivilege;
            else if (string.Compare(right, "InteractiveLogon", opt) == 0)
                userRight = Win32Const.Rights.SeInteractiveLogonRight;
            else if (string.Compare(right, "RemoteInteractiveLogon", opt) == 0)
                userRight = Win32Const.Rights.SeRemoteInteractiveLogonRight;
            else if (string.Compare(right, "Backup", opt) == 0)
                userRight = Win32Const.Rights.SeBackupPrivilege;
            else if (string.Compare(right, "ChangeNotify", opt) == 0)
                userRight = Win32Const.Rights.SeChangeNotifyPrivilege;
            else if (string.Compare(right, "Systemtime", opt) == 0)
                userRight = Win32Const.Rights.SeSystemtimePrivilege;
            else if (string.Compare(right, "TimeZone", opt) == 0)
                userRight = Win32Const.Rights.SeTimeZonePrivilege;
            else if (string.Compare(right, "CreatePagefile", opt) == 0)
                userRight = Win32Const.Rights.SeCreatePagefilePrivilege;
            else if (string.Compare(right, "CreateToken", opt) == 0)
                userRight = Win32Const.Rights.SeCreateTokenPrivilege;
            else if (string.Compare(right, "CreateGlobal", opt) == 0)
                userRight = Win32Const.Rights.SeCreateGlobalPrivilege;
            else if (string.Compare(right, "CreatePermanent", opt) == 0)
                userRight = Win32Const.Rights.SeCreatePermanentPrivilege;
            else if (string.Compare(right, "CreateSymbolicLink", opt) == 0)
                userRight = Win32Const.Rights.SeCreateSymbolicLinkPrivilege;
            else if (string.Compare(right, "Debug", opt) == 0)
                userRight = Win32Const.Rights.SeDebugPrivilege;
            else if (string.Compare(right, "DenyNetworkLogon", opt) == 0)
                userRight = Win32Const.Rights.SeDenyNetworkLogonRight;
            else if (string.Compare(right, "DenyBatchLogon", opt) == 0)
                userRight = Win32Const.Rights.SeDenyBatchLogonRight;
            else if (string.Compare(right, "DenyServiceLogon", opt) == 0)
                userRight = Win32Const.Rights.SeDenyServiceLogonRight;
            else if (string.Compare(right, "DenyInteractiveLogon", opt) == 0)
                userRight = Win32Const.Rights.SeDenyInteractiveLogonRight;
            else if (string.Compare(right, "DenyRemoteInteractiveLogon", opt) == 0)
                userRight = Win32Const.Rights.SeDenyRemoteInteractiveLogonRight;
            else if (string.Compare(right, "EnableDelegation", opt) == 0)
                userRight = Win32Const.Rights.SeEnableDelegationPrivilege;
            else if (string.Compare(right, "RemoteShutdown", opt) == 0)
                userRight = Win32Const.Rights.SeRemoteShutdownPrivilege;
            else if (string.Compare(right, "Audit", opt) == 0)
                userRight = Win32Const.Rights.SeAuditPrivilege;
            else if (string.Compare(right, "Impersonate", opt) == 0)
                userRight = Win32Const.Rights.SeImpersonatePrivilege;
            else if (string.Compare(right, "IncreaseWorkingSet", opt) == 0)
                userRight = Win32Const.Rights.SeIncreaseWorkingSetPrivilege;
            else if (string.Compare(right, "IncreaseBasePriority", opt) == 0)
                userRight = Win32Const.Rights.SeIncreaseBasePriorityPrivilege;
            else if (string.Compare(right, "LoadDriver", opt) == 0)
                userRight = Win32Const.Rights.SeLoadDriverPrivilege;
            else if (string.Compare(right, "LockMemory", opt) == 0)
                userRight = Win32Const.Rights.SeLockMemoryPrivilege;
            else if (string.Compare(right, "BatchLogon", opt) == 0)
                userRight = Win32Const.Rights.SeBatchLogonRight;
            else if (string.Compare(right, "ServiceLogon", opt) == 0)
                userRight = Win32Const.Rights.SeServiceLogonRight;
            else if (string.Compare(right, "Security", opt) == 0)
                userRight = Win32Const.Rights.SeSecurityPrivilege;
            else if (string.Compare(right, "Relabel", opt) == 0)
                userRight = Win32Const.Rights.SeRelabelPrivilege;
            else if (string.Compare(right, "SystemEnvironment", opt) == 0)
                userRight = Win32Const.Rights.SeSystemEnvironmentPrivilege;
            else if (string.Compare(right, "DelegateSessionUserImpersonate", opt) == 0)
                userRight = Win32Const.Rights.SeDelegateSessionUserImpersonatePrivilege;
            else if (string.Compare(right, "ManageVolume", opt) == 0)
                userRight = Win32Const.Rights.SeManageVolumePrivilege;
            else if (string.Compare(right, "ProfileSingleProcess", opt) == 0)
                userRight = Win32Const.Rights.SeProfileSingleProcessPrivilege;
            else if (string.Compare(right, "SystemProfile", opt) == 0)
                userRight = Win32Const.Rights.SeSystemProfilePrivilege;
            else if (string.Compare(right, "UnsolicitedInput", opt) == 0)
                userRight = Win32Const.Rights.SeUnsolicitedInputPrivilege;
            else if (string.Compare(right, "Undock", opt) == 0)
                userRight = Win32Const.Rights.SeUndockPrivilege;
            else if (string.Compare(right, "AssignPrimaryToken", opt) == 0)
                userRight = Win32Const.Rights.SeAssignPrimaryTokenPrivilege;
            else if (string.Compare(right, "Restore", opt) == 0)
                userRight = Win32Const.Rights.SeRestorePrivilege;
            else if (string.Compare(right, "Shutdown", opt) == 0)
                userRight = Win32Const.Rights.SeShutdownPrivilege;
            else if (string.Compare(right, "SyncAgent", opt) == 0)
                userRight = Win32Const.Rights.SeSyncAgentPrivilege;
            else if (string.Compare(right, "TakeOwnership", opt) == 0)
                userRight = Win32Const.Rights.SeTakeOwnershipPrivilege;
            else
                return false;

            return true;
        }


        // Modules
        public static void EnumCommand(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            if (!string.IsNullOrEmpty(options.GetValue("domain")) ||
                !string.IsNullOrEmpty(options.GetValue("username")) ||
                !string.IsNullOrEmpty(options.GetValue("sid")))
            {
                Modules.EnumerateUserRights(
                    options.GetValue("domain"),
                    options.GetValue("username"),
                    options.GetValue("sid"));
            }
            else
            {
                options.GetHelp();
            }
        }


        public static void FindCommand(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            if (options.GetFlag("list"))
            {
                Console.WriteLine();
                Console.WriteLine("Available values for --right option:");
                ListRights();
                Console.WriteLine();
            }
            else if (!string.IsNullOrEmpty(options.GetValue("right")))
            {
                if (ResolveRights(options.GetValue("right"),
                    out Win32Const.Rights userRight))
                {
                    Modules.EnumerateUsersWithRights(userRight);
                }
                else
                {
                    Console.WriteLine("\n[-] Failed to resolve user right.\n");
                }
            }
            else
            {
                options.GetHelp();
            }
        }


        public static void LookupCommand(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            if (!string.IsNullOrEmpty(options.GetValue("domain")) ||
                !string.IsNullOrEmpty(options.GetValue("username")) ||
                !string.IsNullOrEmpty(options.GetValue("sid")))
            {
                Modules.LookupSid(
                    options.GetValue("domain"),
                    options.GetValue("username"),
                    options.GetValue("sid"));
            }
            else
            {
                options.GetHelp();
            }
        }


        public static void ManageCommand(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            if (options.GetFlag("list"))
            {
                Console.WriteLine();
                Console.WriteLine("Available values for --grant and --revoke options:");
                ListRights();
                Console.WriteLine();
            }
            else if (!string.IsNullOrEmpty(options.GetValue("grant")))
            {
                if (!ResolveRights(
                    options.GetValue("grant"),
                    out Win32Const.Rights userRight))
                {
                    Console.WriteLine("\n[!] Failed to resolve user right.\n");
                }
                else
                {
                    Modules.GrantUserRight(
                        options.GetValue("domain"),
                        options.GetValue("username"),
                        options.GetValue("sid"),
                        userRight);
                }
            }
            else if (!string.IsNullOrEmpty(options.GetValue("revoke")))
            {
                if (!ResolveRights(
                    options.GetValue("revoke"),
                    out Win32Const.Rights userRight))
                {
                    Console.WriteLine("\n[!] Failed to resolve user right.\n");
                }
                else
                {
                    Modules.RevokeUserRight(
                        options.GetValue("domain"),
                        options.GetValue("username"),
                        options.GetValue("sid"),
                        userRight);
                }
            }
            else
            {
                options.GetHelp();
            }
        }
    }
}
