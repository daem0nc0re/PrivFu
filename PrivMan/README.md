# PrivMan
This is a tool to manipulate token privileges with kernel driver.

```
PS C:\Works> .\PrivMan.exe -h

PrivMan - Tool to manipulate token privileges.

Usage: PrivMan.exe [Options]

        -h, --help    : Displays this help message.
        -g, --get     : Flag to get token privileges status.
        -p, --pid     : Specifies a PID to manipulate token privileges.
        -d, --disable : Specifies a privilege name string to disable.
        -e, --enable  : Specifies a privilege name string to enable.
        -f, --filter  : Specifies a privilege name string to filter.
        -r, --remove  : Specifies a privilege name string to remove.
```

This tool requires a custom kernel driver in this project:

```
PS C:\Works> sc.exe qc PrivMan
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: PrivMan
        TYPE               : 1  KERNEL_DRIVER
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : \??\C:\Works\PrivManDrv_x64.sys
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : PrivMan
        DEPENDENCIES       :
        SERVICE_START_NAME :
PS C:\Works> sc.exe query PrivMan

SERVICE_NAME: PrivMan
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

To get current token privileges for a specific process, set `-g` flag as follows;

```
PS C:\Works> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

PS C:\Works> .\PrivMan.exe -p $pid -g

[*] Trying to get current token privielges status for 'powershell' (PID: 6788).

PRIVILEGES INFORMATION
----------------------

Privilege Name                State
============================= ===========================
SeShutdownPrivilege           Disabled
SeChangeNotifyPrivilege       Enabled By Default, Enabled
SeUndockPrivilege             Disabled
SeIncreaseWorkingSetPrivilege Disabled
SeTimeZonePrivilege           Disabled

[*] Done.
```

If you want to enable token privileges, specify privilege name pattern to `-e` option.
Privileges not present are automatically added:

```
PS C:\Works> .\PrivMan.exe -p $pid -g

[*] Trying to get current token privielges status for 'powershell' (PID: 6788).

PRIVILEGES INFORMATION
----------------------

Privilege Name                State
============================= ===========================
SeShutdownPrivilege           Disabled
SeChangeNotifyPrivilege       Enabled By Default, Enabled
SeUndockPrivilege             Disabled
SeIncreaseWorkingSetPrivilege Disabled
SeTimeZonePrivilege           Disabled

[*] Done.

PS C:\Works> .\PrivMan.exe -p $pid -e assign

[*] Trying to enable the following privileges for 'powershell' (PID: 6788).

Privilege Name                LUID             Bit Mask
============================= ================ ================
SeAssignPrimaryTokenPrivilege 0000000000000003 0000000000000008

[*] Trying to overwrite SEP_TOKEN_PRIVILEGES:
    [*] Present          : 0000000602880008
    [*] Enabled          : 0000000000800008
    [*] EnabledByDefault : 0000000040800000
[+] Token privileges are enabled successfully.
[*] Done.

PS C:\Works> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeAssignPrimaryTokenPrivilege Replace a process level token        Enabled
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

This tool specifies privileges to manipulate with case insensitive name mathcing.
So, if you want to enable all token privileges, simply set privilege name pattern as `s`:

```
PS C:\Works> .\PrivMan.exe -p $pid -e s

[*] Trying to enable the following privileges for 'powershell' (PID: 6788).

Privilege Name                            LUID             Bit Mask
========================================= ================ ================
SeCreateTokenPrivilege                    0000000000000002 0000000000000004
SeAssignPrimaryTokenPrivilege             0000000000000003 0000000000000008
SeLockMemoryPrivilege                     0000000000000004 0000000000000010
SeIncreaseQuotaPrivilege                  0000000000000005 0000000000000020
SeMachineAccountPrivilege                 0000000000000006 0000000000000040
SeTcbPrivilege                            0000000000000007 0000000000000080
SeSecurityPrivilege                       0000000000000008 0000000000000100
SeTakeOwnershipPrivilege                  0000000000000009 0000000000000200
SeLoadDriverPrivilege                     000000000000000A 0000000000000400
SeSystemProfilePrivilege                  000000000000000B 0000000000000800
SeSystemtimePrivilege                     000000000000000C 0000000000001000
SeProfileSingleProcessPrivilege           000000000000000D 0000000000002000
SeIncreaseBasePriorityPrivilege           000000000000000E 0000000000004000
SeCreatePagefilePrivilege                 000000000000000F 0000000000008000
SeCreatePermanentPrivilege                0000000000000010 0000000000010000
SeBackupPrivilege                         0000000000000011 0000000000020000
SeRestorePrivilege                        0000000000000012 0000000000040000
SeShutdownPrivilege                       0000000000000013 0000000000080000
SeDebugPrivilege                          0000000000000014 0000000000100000
SeAuditPrivilege                          0000000000000015 0000000000200000
SeSystemEnvironmentPrivilege              0000000000000016 0000000000400000
SeChangeNotifyPrivilege                   0000000000000017 0000000000800000
SeRemoteShutdownPrivilege                 0000000000000018 0000000001000000
SeUndockPrivilege                         0000000000000019 0000000002000000
SeSyncAgentPrivilege                      000000000000001A 0000000004000000
SeEnableDelegationPrivilege               000000000000001B 0000000008000000
SeManageVolumePrivilege                   000000000000001C 0000000010000000
SeImpersonatePrivilege                    000000000000001D 0000000020000000
SeCreateGlobalPrivilege                   000000000000001E 0000000040000000
SeTrustedCredManAccessPrivilege           000000000000001F 0000000080000000
SeRelabelPrivilege                        0000000000000020 0000000100000000
SeIncreaseWorkingSetPrivilege             0000000000000021 0000000200000000
SeTimeZonePrivilege                       0000000000000022 0000000400000000
SeCreateSymbolicLinkPrivilege             0000000000000023 0000000800000000
SeDelegateSessionUserImpersonatePrivilege 0000000000000024 0000001000000000

[*] Trying to overwrite SEP_TOKEN_PRIVILEGES:
    [*] Present          : 0000001FFFFFFFFC
    [*] Enabled          : 0000001FFFFFFFFC
    [*] EnabledByDefault : 0000000040800000
[+] Token privileges are enabled successfully.
[*] Done.

PS C:\Works> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeCreateTokenPrivilege                    Create a token object                                              Enabled
SeAssignPrimaryTokenPrivilege             Replace a process level token                                      Enabled
SeLockMemoryPrivilege                     Lock pages in memory                                               Enabled
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeTcbPrivilege                            Act as part of the operating system                                Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeCreatePermanentPrivilege                Create permanent shared objects                                    Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeAuditPrivilege                          Generate security audits                                           Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeSyncAgentPrivilege                      Synchronize directory service data                                 Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeTrustedCredManAccessPrivilege           Access Credential Manager as a trusted caller                      Enabled
SeRelabelPrivilege                        Modify an object label                                             Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```

Comma separated string can be used for privilege name pattern:

```
PS C:\Works> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

PS C:\Works> .\PrivMan.exe -p $pid -e assign,shut

[*] Trying to enable the following privileges for 'powershell' (PID: 2428).

Privilege Name                LUID             Bit Mask
============================= ================ ================
SeAssignPrimaryTokenPrivilege 0000000000000003 0000000000000008
SeShutdownPrivilege           0000000000000013 0000000000080000
SeRemoteShutdownPrivilege     0000000000000018 0000000001000000

[*] Trying to overwrite SEP_TOKEN_PRIVILEGES:
    [*] Present          : 0000000603880008
    [*] Enabled          : 0000000001880008
    [*] EnabledByDefault : 0000000040800000
[+] Token privileges are enabled successfully.
[*] Done.

PS C:\Works> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeAssignPrimaryTokenPrivilege Replace a process level token        Enabled
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system  Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

To disable specific token privileges, use `-d` option as follows:

```
PS C:\Works> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeAssignPrimaryTokenPrivilege Replace a process level token        Enabled
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system  Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

PS C:\Works> .\PrivMan.exe -p $pid -d assign

[*] Trying to disable the following privileges for 'powershell' (PID: 2428).

Privilege Name                LUID             Bit Mask
============================= ================ ================
SeAssignPrimaryTokenPrivilege 0000000000000003 0000000000000008

[*] Trying to overwrite SEP_TOKEN_PRIVILEGES:
    [*] Present          : 0000000603880008
    [*] Enabled          : 0000000001880000
    [*] EnabledByDefault : 0000000040800000
[+] Token privileges are disabled successfully.
[*] Done.

PS C:\Works> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeAssignPrimaryTokenPrivilege Replace a process level token        Disabled
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system  Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

If you remove specific token privileges, use `-r` option as follows:

```
PS C:\Works> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeAssignPrimaryTokenPrivilege Replace a process level token        Disabled
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system  Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

PS C:\Works> .\PrivMan.exe -p $pid -r assign

[*] Trying to remove the following privileges for 'powershell' (PID: 2428).

Privilege Name                LUID             Bit Mask
============================= ================ ================
SeAssignPrimaryTokenPrivilege 0000000000000003 0000000000000008

[*] Trying to overwrite SEP_TOKEN_PRIVILEGES:
    [*] Present          : 0000000603880000
    [*] Enabled          : 0000000001880000
    [*] EnabledByDefault : 0000000040800000
[+] Token privileges are removed successfully.
[*] Done.

PS C:\Works> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system  Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

If you want to remove all token privileges other than you want to remain, use `-f` option as follows:

```
PS C:\Works> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system  Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

PS C:\Works> .\PrivMan.exe -p $pid -f notify

[*] Trying to filter the following privileges for 'powershell' (PID: 2428).

Privilege Name          LUID             Bit Mask
======================= ================ ================
SeChangeNotifyPrivilege 0000000000000017 0000000000800000

[*] Trying to overwrite SEP_TOKEN_PRIVILEGES:
    [*] Present          : 0000000000800000
    [*] Enabled          : 0000000000800000
    [*] EnabledByDefault : 0000000000800000
[+] Token privileges are filtered successfully.
[*] Done.

PS C:\Works> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description              State
======================= ======================== =======
SeChangeNotifyPrivilege Bypass traverse checking Enabled
```