using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UserRightsUtil.Interop
{
    class Win32Const
    {
        [Flags]
        public enum FormatMessageFlags : uint
        {
            FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100,
            FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200,
            FORMAT_MESSAGE_FROM_STRING = 0x00000400,
            FORMAT_MESSAGE_FROM_HMODULE = 0x00000800,
            FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000,
            FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000
        }

        [Flags]
        public enum PolicyAccessRights : uint
        {
            POLICY_VIEW_LOCAL_INFORMATION = 0x00000001,
            POLICY_VIEW_AUDIT_INFORMATION = 0x00000002,
            POLICY_GET_PRIVATE_INFORMATION = 0x00000004,
            POLICY_TRUST_ADMIN = 0x00000008,
            POLICY_CREATE_ACCOUNT = 0x00000010,
            POLICY_CREATE_SECRET = 0x00000020,
            POLICY_CREATE_PRIVILEGE = 0x00000040,
            POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080,
            POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100,
            POLICY_AUDIT_LOG_ADMIN = 0x00000200,
            POLICY_SERVER_ADMIN = 0x00000400,
            POLICY_LOOKUP_NAMES = 0x00000800,
            GENERIC_READ = 0x00020006,
            GENERIC_WRITE = 0x000207F8,
            GENERIC_EXECUTE_POLICY = 0x00020801,
            POLICY_ALL_ACCESS = 0x000F0FFF
        }

        public enum Rights
        {
            SeTrustedCredManAccessPrivilege,             // Access Credential Manager as a trusted caller
            SeNetworkLogonRight,                         // Access this computer from the network
            SeTcbPrivilege,                              // Act as part of the operating system
            SeMachineAccountPrivilege,                   // Add workstations to domain
            SeIncreaseQuotaPrivilege,                    // Adjust memory quotas for a process
            SeInteractiveLogonRight,                     // Allow log on locally
            SeRemoteInteractiveLogonRight,               // Allow log on through Remote Desktop Services
            SeBackupPrivilege,                           // Back up files and directories
            SeChangeNotifyPrivilege,                     // Bypass traverse checking
            SeSystemtimePrivilege,                       // Change the system time
            SeTimeZonePrivilege,                         // Change the time zone
            SeCreatePagefilePrivilege,                   // Create a pagefile
            SeCreateTokenPrivilege,                      // Create a token object
            SeCreateGlobalPrivilege,                     // Create global objects
            SeCreatePermanentPrivilege,                  // Create permanent shared objects
            SeCreateSymbolicLinkPrivilege,               // Create symbolic links
            SeDebugPrivilege,                            // Debug programs
            SeDenyNetworkLogonRight,                     // Deny access this computer from the network
            SeDenyBatchLogonRight,                       // Deny log on as a batch job
            SeDenyServiceLogonRight,                     // Deny log on as a service
            SeDenyInteractiveLogonRight,                 // Deny log on locally
            SeDenyRemoteInteractiveLogonRight,           // Deny log on through Remote Desktop Services
            SeEnableDelegationPrivilege,                 // Enable computer and user accounts to be trusted for delegation
            SeRemoteShutdownPrivilege,                   // Force shutdown from a remote system
            SeAuditPrivilege,                            // Generate security audits
            SeImpersonatePrivilege,                      // Impersonate a client after authentication
            SeIncreaseWorkingSetPrivilege,               // Increase a process working set
            SeIncreaseBasePriorityPrivilege,             // Increase scheduling priority
            SeLoadDriverPrivilege,                       // Load and unload device drivers
            SeLockMemoryPrivilege,                       // Lock pages in memory
            SeBatchLogonRight,                           // Log on as a batch job
            SeServiceLogonRight,                         // Log on as a service
            SeSecurityPrivilege,                         // Manage auditing and security log
            SeRelabelPrivilege,                          // Modify an object label
            SeSystemEnvironmentPrivilege,                // Modify firmware environment values
            SeDelegateSessionUserImpersonatePrivilege,   // Obtain an impersonation token for another user in the same session
            SeManageVolumePrivilege,                     // Perform volume maintenance tasks
            SeProfileSingleProcessPrivilege,             // Profile single process
            SeSystemProfilePrivilege,                    // Profile system performance
            SeUnsolicitedInputPrivilege,                 // "Read unsolicited input from a terminal device"
            SeUndockPrivilege,                           // Remove computer from docking station
            SeAssignPrimaryTokenPrivilege,               // Replace a process level token
            SeRestorePrivilege,                          // Restore files and directories
            SeShutdownPrivilege,                         // Shut down the system
            SeSyncAgentPrivilege,                        // Synchronize directory service data
            SeTakeOwnershipPrivilege                     // Take ownership of files or other objects
        }

        public enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

        // NTSTATUS
        public const uint STATUS_SUCCESS = 0;

        // Win32Error
        public const int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;

        // Flag for netapi32.dll API
        public const uint NERR_Success = 0;
        public const int LG_INCLUDE_INDIRECT = 0x0001;
        public const int MAX_PREFERRED_LENGTH = -1;
    }
}
