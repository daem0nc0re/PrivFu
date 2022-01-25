# PrivFu
Kernel mode WinDbg extension and PoCs for testing how token privileges work.

There are notable repository and articles about token privilege abuse such [Grzegorz Tworek](https://twitter.com/0gtweet)'s [Priv2Admin](https://github.com/gtworek/Priv2Admin).
Codes in this repository are intended to help investigate how token privileges work.


## Table Of Contents

- [PrivFu](#privfu)
  - [PrivEditor](#priveditor)
    - [getps Command](#getps-command)
    - [getpriv Command](#getpriv-command)
    - [addpriv Command](#addpriv-command)
    - [rmpriv Command](#rmpriv-command)
    - [enablepriv Command](#enablepriv-command)
    - [disablepriv Command](#disablepriv-command)
    - [enableall Command](#enableall-command)
    - [disableall Command](#disableall-command)
  - [PrivilegedOperations](#privilegedoperations)
  - [SwitchPriv](#switchpriv)
  - [TrustExec](#trustexec)
    - [exec Module](#exec-module)
    - [sid Module](#sid-module)
  - [Reference](#reference)
  - [Acknowledgments](#acknowledgments)

## PrivEditor

[Back to Top](#privfu)

[Project](./PrivEditor)

PrivEditor is kernel mode WinDbg extension to manipulate token privilege of specific process.
This extension makes it easy to configure the token privilege you want to investigate:

```
0: kd> .load C:\dev\PrivEditor\x64\Release\PrivEditor.dll

PrivEditor - Kernel Mode WinDbg extension for token privilege edit.

Commands :
    + !getps       : List processes in target system.
    + !getpriv     : List privileges of a process.
    + !addpriv     : Add privilege(s) to a process.
    + !rmpriv      : Remove privilege(s) from a process.
    + !enablepriv  : Enable privilege(s) of a process.
    + !disablepriv : Disable privilege(s) of a process.
    + !enableall   : Enable all privileges available to a process.
    + !disableall  : Disable all privileges available to a process.

[*] To see command help, execute "!<Command> help" or "!<Command> /?".
```

> __WARNING__ This extension supports both x64 and x86 OS as debug target, but not supports x86 WinDbg.


### getps Command
This command is to list processes in your target system:

```
0: kd> !getps /?

!getps - List processes in target system.

Usage : !getps [Process Name]

    Process Name : (OPTIONAL) Specifies filter string for process name.
```

If you execute this command without any arguments, this command list all processes in your target system as follows:

```
0: kd> !getps

     PID        nt!_EPROCESS nt!_SEP_TOKEN_PRIVILEGES Process Name
======== =================== ======================== ============
       0 0xfffff805`81233630      0x00000000`00000000 System Idle Process
       4 0xffffd60f`ec068380      0xffffaf00`cec07a40 System
      68 0xffffd60f`f1780480      0xffffaf00`d3b290a0 svchost.exe
      88 0xffffd60f`ec0db080      0xffffaf00`cec0d080 Registry
     324 0xffffd60f`ef342040      0xffffaf00`d0416080 smss.exe
     348 0xffffd60f`f052f100      0xffffaf00`d25d30a0 dwm.exe
     408 0xffffd60f`eca8e140      0xffffaf00`d21bd930 csrss.exe
     480 0xffffd60f`f05a8340      0xffffaf00`d2568670 svchost.exe
     484 0xffffd60f`efcd60c0      0xffffaf00`d06430e0 wininit.exe
     500 0xffffd60f`efd130c0      0xffffaf00`d23100a0 csrss.exe
     580 0xffffd60f`efdc0080      0xffffaf00`d2266630 winlogon.exe

--snip--
```

If you want to know specific processes, set string filter as follows.
The filter works with forward matching and case insensitive:

```
0: kd> !getps micro

     PID        nt!_EPROCESS nt!_SEP_TOKEN_PRIVILEGES Process Name
======== =================== ======================== ============
    4568 0xffffd60f`f14ed080      0xffffaf00`d3db60a0 MicrosoftEdge.exe
    4884 0xffffd60f`f1647080      0xffffaf00`d3fc17b0 MicrosoftEdgeCP.exe
    4892 0xffffd60f`f1685080      0xffffaf00`d3fc07b0 MicrosoftEdgeSH.exe
```


### getriv Command
This command is to list token privileges of a specific process:

```
0: kd> !getpriv /?

!getpriv - List privileges of a process.

Usage : !getpriv <PID>

    PID : Specifies target process ID.
```

To use this command, you need to set a target process ID in decimal format as follows:

```
0: kd> !getpriv 5704

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Disabled

[*] PID                      : 5704
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd60f`f141e4c0
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffaf00`d4a0c0a0
```


### addpriv Command
This command is to add token privilege(s) to a specific process:

```
0: kd> !addpriv /?

!addpriv - Add privilege(s) to a process.

Usage : !addpriv <PID> <Privilege>

    PID       : Specifies target process ID.
    Privilege : Specifies privilege to enable (case insensitive). Available privileges are following.

        + CreateToken                    : SeCreateTokenPrivilege.
        + AssignPrimaryToken             : SeAssignPrimaryTokenPrivilege.
        + LockMemory                     : SeLockMemoryPrivilege.
        + IncreaseQuota                  : SeIncreaseQuotaPrivilege.
        + MachineAccount                 : SeMachineAccountPrivilege.
        + Tcb                            : SeTcbPrivilege.
        + Security                       : SeSecurityPrivilege.
        + TakeOwnership                  : SeTakeOwnershipPrivilege.
        + LoadDriver                     : SeLoadDriverPrivilege.
        + SystemProfile                  : SeSystemProfilePrivilege.
        + Systemtime                     : SeSystemtimePrivilege.
        + ProfileSingleProcess           : SeProfileSingleProcessPrivilege.
        + IncreaseBasePriority           : SeIncreaseBasePriorityPrivilege.
        + CreatePagefile                 : SeCreatePagefilePrivilege.
        + CreatePermanent                : SeCreatePermanentPrivilege.
        + Backup                         : SeBackupPrivilege.
        + Restore                        : SeRestorePrivilege.
        + Shutdown                       : SeShutdownPrivilege.
        + Debug                          : SeDebugPrivilege.
        + Audit                          : SeAuditPrivilege.
        + SystemEnvironment              : SeSystemEnvironmentPrivilege.
        + ChangeNotify                   : SeChangeNotifyPrivilege.
        + RemoteShutdown                 : SeRemoteShutdownPrivilege.
        + Undock                         : SeUndockPrivilege.
        + SyncAgent                      : SeSyncAgentPrivilege.
        + EnableDelegation               : SeEnableDelegationPrivilege.
        + ManageVolume                   : SeManageVolumePrivilege.
        + Impersonate                    : SeImpersonatePrivilege.
        + CreateGlobal                   : SeCreateGlobalPrivilege.
        + TrustedCredManAccess           : SeTrustedCredManAccessPrivilege.
        + Relabel                        : SeRelabelPrivilege.
        + IncreaseWorkingSet             : SeIncreaseWorkingSetPrivilege.
        + TimeZone                       : SeTimeZonePrivilege.
        + CreateSymbolicLink             : SeCreateSymbolicLinkPrivilege.
        + DelegateSessionUserImpersonate : SeDelegateSessionUserImpersonatePrivilege.
        + All                            : All privileges.
```

For example, if you want to set SeDebugPrivilege to a specific process, set a target process ID for the first argument and shorten privilege name `debug` as listed in the help message for second argument as follows:

```
0: kd> !getpriv 5704

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Disabled

[*] PID                      : 5704
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd60f`f141e4c0
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffaf00`d4a0c0a0

0: kd> !addpriv 5704 debug

[>] Trying to add SeDebugPrivilege.
[*] Completed.

0: kd> !getpriv 5704

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeDebugPrivilege                           Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Disabled

[*] PID                      : 5704
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd60f`f141e4c0
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffaf00`d4a0c0a0
```

The privilege name argument is case insensitive.

If you want to add all token privileges at a time, set `all` as the privilege name argument:

```
0: kd> !addpriv 5704 all

[>] Trying to add all privileges.
[*] Completed.

0: kd> !getpriv 5704

Privilege Name                             State
========================================== ========
SeCreateTokenPrivilege                     Disabled
SeAssignPrimaryTokenPrivilege              Disabled
SeLockMemoryPrivilege                      Disabled
SeIncreaseQuotaPrivilege                   Disabled
SeMachineAccountPrivilege                  Disabled
SeTcbPrivilege                             Disabled
SeSecurityPrivilege                        Disabled

--snip--
```


### rmpriv Command
This command is to remove token privilege(s) from a specific process:

```
0: kd> !rmpriv /?

!rmpriv - Remove privilege(s) from a process.

Usage : !rmpriv <PID> <Privilege>

    PID       : Specifies target process ID.
    Privilege : Specifies privilege to enable (case insensitive). Available privileges are following.

        + CreateToken                    : SeCreateTokenPrivilege.
        + AssignPrimaryToken             : SeAssignPrimaryTokenPrivilege.
        + LockMemory                     : SeLockMemoryPrivilege.

--snip--
```

If you want to remove SeChangeNotifyPrivilege, execute this command as follows:

```
0: kd> !getpriv 352

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Disabled

[*] PID                      : 352
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd60f`f17c6080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffaf00`d3468770

0: kd> !rmpriv 352 changenotify

[>] Trying to remove SeChangeNotifyPrivilege.
[*] Completed.

0: kd> !getpriv 352

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Disabled

[*] PID                      : 352
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd60f`f17c6080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffaf00`d3468770
```

As `!addpriv` command, you can remove all token privileges at a time by setting `all` as the privilege name argument:

```
0: kd> !rmpriv 352 all

[>] Trying to remove all privileges.
[*] Completed.

0: kd> !getpriv 352

Privilege Name                             State
========================================== ========

[*] PID                      : 352
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd60f`f17c6080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffaf00`d3468770
```


### enablepriv Command
This command is to enable token privilege(s) of a specific process:

```
0: kd> !enablepriv /?

!enablepriv - Enable privilege(s) of a process.

Usage : !enablepriv <PID> <Privilege>

    PID       : Specifies target process ID.
    Privilege : Specifies privilege to enable (case insensitive). Available privileges are following.

        + CreateToken                    : SeCreateTokenPrivilege.
        + AssignPrimaryToken             : SeAssignPrimaryTokenPrivilege.
        + LockMemory                     : SeLockMemoryPrivilege.

--snip--
```

The first argument is for process ID, and the second is for token privilege name:

```
0: kd> !getpriv 1932

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Disabled

[*] PID                      : 1932
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd60f`f17c6080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffaf00`d4a040a0

0: kd> !enablepriv 1932 timezone

[>] Trying to enable SeTimeZonePrivilege.
[*] Completed.

0: kd> !getpriv 1932

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Enabled

[*] PID                      : 1932
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd60f`f17c6080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffaf00`d4a040a0
```

If you tried to enable privilege(s), not added yet, this command adds it automatically:

```
0: kd> !getpriv 1932

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Enabled

[*] PID                      : 1932
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd60f`f17c6080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffaf00`d4a040a0

0: kd> !enablepriv 1932 debug

[*] SeDebugPrivilege is not present.
[>] Trying to add SeDebugPrivilege.
[>] Trying to enable SeDebugPrivilege.
[*] Completed.

0: kd> !getpriv 1932

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeDebugPrivilege                           Enabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Enabled

[*] PID                      : 1932
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd60f`f17c6080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffaf00`d4a040a0
```


### disablepriv Command
This command is to disable token privilege(s) of a specific process:

```
0: kd> !disablepriv /?

!disablepriv - Disable privilege(s) of a process.

Usage : !disablepriv <PID> <Privilege>

    PID       : Specifies target process ID.
    Privilege : Specifies privilege to enable (case insensitive). Available privileges are following.

        + CreateToken                    : SeCreateTokenPrivilege.
        + AssignPrimaryToken             : SeAssignPrimaryTokenPrivilege.
        + LockMemory                     : SeLockMemoryPrivilege.

--snip--
```

To use this command, set a target process ID for the first argument and token privilege name for the second argument:

```
0: kd> !getpriv 1932

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeDebugPrivilege                           Enabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Enabled

[*] PID                      : 1932
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd60f`f17c6080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffaf00`d4a040a0

0: kd> !disablepriv 1932 debug

[>] Trying to disable SeDebugPrivilege.
[*] Completed.

0: kd> !getpriv 1932

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeDebugPrivilege                           Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Enabled

[*] PID                      : 1932
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd60f`f17c6080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffaf00`d4a040a0
```


### enableall Command
This command is to enable all token privilege(s) available for a specific process:

```
0: kd> !enableall /?

!enableall - Enable all privileges available to a process.

Usage : !enableall <PID>

    PID       : Specifies target process ID.
```

It works as follows:

```
0: kd> !getpriv 3792

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Disabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled

[*] PID                      : 3792
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd507`aaed9080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffb708`d72ab8a0

0: kd> !enableall 3792

[>] Trying to enable all available privileges.
[*] Completed.

0: kd> !getpriv 3792

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Enabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Enabled
SeIncreaseWorkingSetPrivilege              Enabled

[*] PID                      : 3792
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd507`aaed9080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffb708`d72ab8a0
```


### disableall Command
This command is to disable all token privilege(s) for a specific process:

```
0: kd> !disableall /?

!disableall - Disable all privileges available to a process.

Usage : !disableall <PID>

    PID : Specifies target process ID.
```

This command is equivalent to `!disablepriv <PID> all`. Works as follows:

```
0: kd> !getpriv 3792

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Enabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Enabled
SeIncreaseWorkingSetPrivilege              Enabled

[*] PID                      : 3792
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd507`aaed9080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffb708`d72ab8a0

0: kd> !disableall 3792

[>] Trying to disable all available privileges.
[*] Completed.

0: kd> !getpriv 3792

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Disabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled

[*] PID                      : 3792
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd507`aaed9080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffb708`d72ab8a0
```


## PrivilegedOperations

[Back to Top](#privfu)

[Project](./PrivilegedOperations)

This project is PoCs for sensitive token privileges such SeDebugPrivilege.
Currently, released PoCs for a part of them.

| Program Name | Description |
| :--- | :--- |
| [SeCreateTokenPrivilegePoC](./PrivilegedOperations/SeCreateTokenPrivilegePoC) | This PoC creates a elevated token by SeCreateTokenPrivilege. |
| [SeRestorePrivilegePoC](./PrivilegedOperations/SeRestorePrivilegePoC) | This PoC opens a handle to privileged registry key (`HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice\Parameters`) with `REG_OPTION_BACKUP_RESTORE` flag by SeRestorePrivilege. |
| [SeDebugPrivilegePoC](./PrivilegedOperations/SeDebugPrivilegePoC) | This PoC opens a handle to winlogon.exe by SeDebugPrivilege. |


## SwitchPriv

[Back to Top](#privfu)

[Project](./SwitchPriv)

This tool is to enable or disable specific token privileges for a process:

```
C:\dev>SwitchPriv.exe

SwitchPriv - Tool to control token privileges.

Usage: SwitchPriv.exe [Options]

        -h, --help    : Displays this help message.
        -e, --enable  : Specifies token privilege to enable. Case insensitive.
        -d, --disable : Specifies token privilege to disable. Case insensitive.
        -p, --pid     : Specifies the target PID. Default specifies PPID.
        -g, --get     : Flag to get available privileges for the target process.
        -l, --list    : Flag to list values for --enable or --disable option.
```

To list values for `--enable` or `--disable` option, execute this tool with `--list` flag as follows:

```
C:\dev>SwitchPriv.exe -l

Available values for --enable or --disable option:

    + CreateToken                    : Specifies SeCreateTokenPrivilege.
    + AssignPrimaryToken             : Specifies SeAssignPrimaryTokenPrivilege.
    + LockMemory                     : Specifies SeLockMemoryPrivilege.
    + IncreaseQuota                  : Specifies SeIncreaseQuotaPrivilege.
    + MachineAccount                 : Specifies SeMachineAccountPrivilege.
    + Tcb                            : Specifies SeTcbPrivilege.
    + Security                       : Specifies SeSecurityPrivilege.
    + TakeOwnership                  : Specifies SeTakeOwnershipPrivilege.

--snip--
```

If you want to control privilege for a remote process, specify the target PID as follows.
For example, to enable SeUndockPrivilege for PID 7584, execute with `--enable` option as follows:

```
C:\dev>SwitchPriv.exe -p 7584 -e undock

[>] Trying to enable SeUndockPrivilege.
    |-> Target PID   : 7584
    |-> Process Name : notepad

[+] SeUndockPrivilege is enabled successfully.
```

To list current token privileges for the target process, execute with `--get` flag as follws:

```
C:\dev>SwitchPriv.exe -p 7584 -g

[>] Trying to get available token privilege(s) for the target process.
    |-> Target PID   : 7584
    |-> Process Name : notepad

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Enabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Disabled
```

To enable SeChangeNotifyPrivilege, execute with `--disable` option as follows:

```
C:\dev>SwitchPriv.exe -p 7584 -d changenotify

[>] Trying to disable SeChangeNotifyPrivilege.
    |-> Target PID   : 7584
    |-> Process Name : notepad

[+] SeChangeNotifyPrivilege is disabled successfully.


C:\dev>SwitchPriv.exe -p 7584 -g

[>] Trying to get available token privilege(s) for the target process.
    |-> Target PID   : 7584
    |-> Process Name : notepad

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Disabled
SeUndockPrivilege                          Enabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Disabled
```

If you don't specify `--pid` option, targets parent process of this tool as follows:

```
C:\dev>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

C:\dev>SwitchPriv.exe -e timezone

[>] Trying to enable SeTimeZonePrivilege.
    |-> Target PID   : 2752
    |-> Process Name : cmd

[+] SeTimeZonePrivilege is enabled successfully.


C:\dev>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Enabled

C:\dev>SwitchPriv.exe -g

[>] Trying to get available token privilege(s) for the target process.
    |-> Target PID   : 2752
    |-> Process Name : cmd

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Enabled
```

To enable or disable all available token privileges, specify `all` as the value for `--enable` or `--disable` option:

```
C:\dev>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Enabled

C:\dev>SwitchPriv.exe -e all

[>] Trying to enable all token privileges.
    |-> Target PID   : 15240
    |-> Process Name : cmd

[+] SeShutdownPrivilege is enabled successfully.
[+] SeUndockPrivilege is enabled successfully.
[+] SeIncreaseWorkingSetPrivilege is enabled successfully.
[*] Done.


C:\dev>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== =======
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
SeTimeZonePrivilege           Change the time zone                 Enabled
```


## TrustExec

[Back to Top](#privfu)

[Project](./TrustExec)

This tool is to execute process as TrustedInstaller group account.
Original PoC is [Grzegorz Tworek](https://twitter.com/0gtweet)'s [TrustedInstallerCmd2.c](https://github.com/gtworek/PSBits/blob/master/VirtualAccounts/TrustedInstallerCmd2.c).
I ported it to C# and rebuilt it as a tool.
Most of operations require administrative privilege (`SeDebugPrivilege`, `SeImpersonatePrivilege` and High Mandatory Level):

```
C:\dev>TrustExec.exe

TrustExec - Tool to investigate TrustedInstaller capability.

Usage: TrustExec.exe [Options]

        -h, --help   : Displays this help message.
        -m, --module : Specifies module name.

Available Modules:

    + exec - Run process as "NT SERVICE\TrustedInstaller".
    + sid  - Add or remove virtual account's SID.

[*] To see help for each modules, specify "-m <Module> -h" as arguments.
```

### exec Module
This module is to execute process as TrustedInstaller group account:

```
C:\dev>TrustExec.exe -m exec -h

TrustExec - Help for "exec" command.

Usage: TrustExec.exe -m exec [Options]

        -h, --help     : Displays this help message.
        -s, --shell    : Flag for interactive shell.
        -c, --command  : Specifies command to execute.
        -d, --domain   : Specifies domain name to add. Default value is "DefaultDomain".
        -u, --username : Specifies username to add. Default value is "DefaultUser".
        -i, --id       : Specifies RID for virtual group. Default value is "110".
        -f, --full     : Flag to enable all available privileges.
```

This module create a virtual accound to impersonate as TrustedInstaller group account.
Tto get interactive shell, set `-s` flag. If you don't specify domain name (`-d` option), username (`-u`) and RID (`-i` option), this module create a virtual account `DefaultDomain\DefaultUser`. Default SID for domain is `S-1-5-110` and for user is `S-1-5-110-110`:

```
C:\dev>TrustExec.exe -m exec -s

[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to impersonate as smss.exe.
[>] Trying to enable SeAssignPrimaryTokenPrivilege.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[>] Trying to enable SeIncreaseQuotaPrivilege.
[+] SeIncreaseQuotaPrivilege is enabled successfully.
[+] Impersonation is successful.
[>] Trying to generate token group information.
[>] Trying to add virtual domain and user.
    |-> Domain   : DefaultDomain (S-1-5-110)
    |-> Username : DefaultUser (S-1-5-110-110)
[+] Added virtual domain and user.
[>] Trying to logon as DefaultDomain\DefaultUser.
[>] Trying to create process.

Microsoft Windows [Version 10.0.18362.30]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\dev>whoami /user

USER INFORMATION
----------------

User Name                 SID
========================= =============
defaultdomain\defaultuser S-1-5-110-110

C:\dev>whoami /groups | findstr /i trusted
NT SERVICE\TrustedInstaller            Well-known group S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464 Enabled by default, Enabled group, Group owner

C:\dev>exit

[>] Exit.
[!] Added virtual domain and account are not removed automatically.
    |-> To remove added virtual account SID : TrustExec.exe -m sid -r -d DefaultDomain -u DefaultUser
    |-> To remove added virtual domain SID  : TrustExec.exe -m sid -r -d DefaultDomain
```

You can change domain name and username, use `-d` option and `-u` option.
To change RID in SID, use `-i` option as follows:

```
C:\dev>TrustExec.exe -m exec -s -d VirtualDomain -u VirtualAdmin -i 92

[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to impersonate as smss.exe.
[>] Trying to enable SeAssignPrimaryTokenPrivilege.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[>] Trying to enable SeIncreaseQuotaPrivilege.
[+] SeIncreaseQuotaPrivilege is enabled successfully.
[+] Impersonation is successful.
[>] Trying to generate token group information.
[>] Trying to add virtual group and account.
    |-> Domain   : VirtualDomain (S-1-5-92)
    |-> Username : VirtualAdmin (S-1-5-92-110)
[+] Added virtual group and account.
[>] Trying to logon as VirtualDomain\VirtualAdmin.
[>] Trying to create process.

Microsoft Windows [Version 10.0.18362.30]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\dev>whoami /user

USER INFORMATION
----------------

User Name                  SID
========================== ============
virtualdomain\virtualadmin S-1-5-92-110
```

If you want to execute single command, use `-c` option without `-s` flag as follows:

```
C:\dev>TrustExec.exe -m exec -c "whoami /user"

[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to impersonate as smss.exe.
[>] Trying to enable SeAssignPrimaryTokenPrivilege.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[>] Trying to enable SeIncreaseQuotaPrivilege.
[+] SeIncreaseQuotaPrivilege is enabled successfully.
[+] Impersonation is successful.
[>] Trying to generate token group information.
[>] Trying to add virtual group and account.
    |-> Domain   : DefaultDomain (S-1-5-110)
    |-> Username : DefaultUser (S-1-5-110-110)
[*] S-1-5-110 or DefaultDomain maybe already exists or invalid.
[>] Trying to logon as DefaultDomain\DefaultUser.
[>] Trying to create process.


USER INFORMATION
----------------

User Name                 SID
========================= =============
defaultdomain\defaultuser S-1-5-110-110

[>] Exit.
[!] Added virtual domain and account are not removed automatically.
    |-> To remove added virtual account SID : TrustExec.exe -m sid -r -d DefaultDomain -u DefaultUser
    |-> To remove added virtual domain SID  : TrustExec.exe -m sid -r -d DefaultDomain
```

If you want to enable all available privileges, set `-f` flag as follows:

```
C:\dev>TrustExec.exe -m exec -c "whoami /priv" -f

[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to impersonate as smss.exe.
[>] Trying to enable SeAssignPrimaryTokenPrivilege.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[>] Trying to enable SeIncreaseQuotaPrivilege.
[+] SeIncreaseQuotaPrivilege is enabled successfully.
[+] Impersonation is successful.
[>] Trying to generate token group information.
[>] Trying to add virtual domain and user.
    |-> Domain   : DefaultDomain (S-1-5-110)
    |-> Username : DefaultUser (S-1-5-110-110)
[+] Added virtual domain and user.
[>] Trying to logon as DefaultDomain\DefaultUser.
[>] Trying to enable SeIncreaseQuotaPrivilege.
[+] SeIncreaseQuotaPrivilege is enabled successfully.
[>] Trying to enable SeSecurityPrivilege.
[+] SeSecurityPrivilege is enabled successfully.
[>] Trying to enable SeTakeOwnershipPrivilege.
[+] SeTakeOwnershipPrivilege is enabled successfully.
[>] Trying to enable SeLoadDriverPrivilege.
[+] SeLoadDriverPrivilege is enabled successfully.
[>] Trying to enable SeSystemProfilePrivilege.
[+] SeSystemProfilePrivilege is enabled successfully.
[>] Trying to enable SeSystemtimePrivilege.
[+] SeSystemtimePrivilege is enabled successfully.
[>] Trying to enable SeProfileSingleProcessPrivilege.
[+] SeProfileSingleProcessPrivilege is enabled successfully.
[>] Trying to enable SeIncreaseBasePriorityPrivilege.
[+] SeIncreaseBasePriorityPrivilege is enabled successfully.
[>] Trying to enable SeCreatePagefilePrivilege.
[+] SeCreatePagefilePrivilege is enabled successfully.
[>] Trying to enable SeBackupPrivilege.
[+] SeBackupPrivilege is enabled successfully.
[>] Trying to enable SeRestorePrivilege.
[+] SeRestorePrivilege is enabled successfully.
[>] Trying to enable SeShutdownPrivilege.
[+] SeShutdownPrivilege is enabled successfully.
[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to enable SeSystemEnvironmentPrivilege.
[+] SeSystemEnvironmentPrivilege is enabled successfully.
[>] Trying to enable SeRemoteShutdownPrivilege.
[+] SeRemoteShutdownPrivilege is enabled successfully.
[>] Trying to enable SeUndockPrivilege.
[+] SeUndockPrivilege is enabled successfully.
[>] Trying to enable SeManageVolumePrivilege.
[+] SeManageVolumePrivilege is enabled successfully.
[>] Trying to enable SeIncreaseWorkingSetPrivilege.
[+] SeIncreaseWorkingSetPrivilege is enabled successfully.
[>] Trying to enable SeTimeZonePrivilege.
[+] SeTimeZonePrivilege is enabled successfully.
[>] Trying to enable SeCreateSymbolicLinkPrivilege.
[+] SeCreateSymbolicLinkPrivilege is enabled successfully.
[>] Trying to enable SeDelegateSessionUserImpersonatePrivilege.
[+] SeDelegateSessionUserImpersonatePrivilege is enabled successfully.
[>] Trying to create process.


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled

[>] Exit.
[!] Added virtual domain and account are not removed automatically.
    |-> To remove added virtual account SID : TrustExec.exe -m sid -r -d DefaultDomain -u DefaultUser
    |-> To remove added virtual domain SID  : TrustExec.exe -m sid -r -d DefaultDomain
```

Added domain and username are not removed automatically.
If you want to remove them, run the `sid` module as shown in the last output.


### sid Module
This module is to manage virtual account created by this tool:

```
C:\dev>TrustExec.exe -m sid -h

TrustExec - Help for "sid" command.

Usage: TrustExec.exe -m sid [Options]

        -h, --help     : Displays this help message.
        -a, --add      : Flag to add virtual account's SID.
        -r, --remove   : Flag to remove virtual account's SID.
        -d, --domain   : Specifies domain name to add or remove. Default value is null.
        -u, --username : Specifies username to add or remove. Default value is null.
        -i, --id       : Specifies RID for virtual domain to add. Default value is "110".
        -s, --sid      : Specifies SID to lookup.
        -l, --lookup   : Flag to lookup SID or account name in local system.
```

To lookup SID, set `-l` flag. If you want to lookup domain or username from SID, specify SID with `-s` option as follows:

```
C:\dev>TrustExec.exe -m sid -l -s S-1-5-18

[*] Result : NT AUTHORITY\SYSTEM (SID : S-1-5-18)
```

If you want to lookup SID from domain name, specify domain name with `-d` option as follows:

```
C:\dev>TrustExec.exe -m sid -l -d VirtualDomain

[*] Result : virtualdomain (SID : S-1-5-92)
```

If you want to lookup SID from domain name and username, specify domain name with `-d` option and username with `-u` option as follows:

```
C:\dev>TrustExec.exe -m sid -l -d defaultdomain -u defaultuser

[*] Result : defaultdomain\defaultuser (SID : S-1-5-110-110)
```

To remove virutal account, set `-r` flag.
Domain name to remove is specified with `-d` option, username is specified with `-u` option:

```
C:\dev>TrustExec.exe -m sid -r -d defaultdomain -u defaultuser

[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to impersonate as smss.exe.
[>] Trying to enable SeAssignPrimaryTokenPrivilege.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[>] Trying to enable SeIncreaseQuotaPrivilege.
[+] SeIncreaseQuotaPrivilege is enabled successfully.
[+] Impersonation is successful.
[>] Trying to remove SID.
    |-> Domain   : defaultdomain
    |-> Username : defaultuser
[+] Requested SID is removed successfully.


C:\dev>TrustExec.exe -m sid -r -d defaultdomain

[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to impersonate as smss.exe.
[>] Trying to enable SeAssignPrimaryTokenPrivilege.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[>] Trying to enable SeIncreaseQuotaPrivilege.
[+] SeIncreaseQuotaPrivilege is enabled successfully.
[+] Impersonation is successful.
[>] Trying to remove SID.
    |-> Domain   : defaultdomain
[+] Requested SID is removed successfully.
```

> __WARNING__ Deleted SIDs may appear to remain until rebooting the OS.


If you want add domain or user SID, set `-a` flag as follows:

```
C:\dev>TrustExec.exe -m sid -a -d virtualworld -u virtualadmin -i 97

[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to impersonate as smss.exe.
[>] Trying to enable SeAssignPrimaryTokenPrivilege.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[>] Trying to enable SeIncreaseQuotaPrivilege.
[+] SeIncreaseQuotaPrivilege is enabled successfully.
[+] Impersonation is successful.
[>] Trying to add virtual group and account.
    |-> Domain   : virtualworld (S-1-5-97)
    |-> Username : virtualadmin (S-1-5-97-110)
[+] Added virtual group and account.

C:\dev>TrustExec.exe -m sid -l -s S-1-5-97

[*] Result : virtualworld (SID : S-1-5-97)


C:\dev>TrustExec.exe -m sid -l -s S-1-5-97-110

[*] Result : virtualworld\virtualadmin (SID : S-1-5-97-110)
```


## Reference

[Back to Top](#privfu)

- [Priv2Admin](https://github.com/gtworek/Priv2Admin) and [PSBits](https://github.com/gtworek/PSBits) by [Grzegorz Tworek](https://twitter.com/0gtweet)
- [Abusing Token Privileges For LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) by [Bryan Alexander](https://twitter.com/dronesec) and [Steve Breen](https://twitter.com/breenmachine)
- [whoami /priv](https://github.com/decoder-it/whoami-priv-Hackinparis2019) by [Andrea Pierini](https://twitter.com/decoder_it)


## Acknowledgments

[Back to Top](#privfu)

Thanks for your advices about WinDbg extension programming:

- Pavel Yosifovich ([@zodiacon](https://twitter.com/zodiacon)) 

Thanks for your notable research:

- Grzegorz Tworek ([@0gtweet](https://twitter.com/0gtweet))
- Bryan Alexander ([@dronesec](https://twitter.com/dronesec))
- Steve Breen ([@breenmachine](https://twitter.com/breenmachine))
- Andrea Pierini ([@decoder_it](https://twitter.com/decoder_it))
