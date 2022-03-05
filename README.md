# PrivFu
Kernel mode WinDbg extension and PoCs for testing how token privileges work.

There are notable repository and articles about token privilege abuse such [Grzegorz Tworek](https://twitter.com/0gtweet)'s [Priv2Admin](https://github.com/gtworek/Priv2Admin).
Codes in this repository are intended to help investigate how token privileges work.


## Table Of Contents

- [PrivFu](#privfu)
  - [KernelWritePoCs](#KernelWritePoCs)
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
  - [UserRightsUtil](#userrightsutil)
    - [enum Module](#enum-module)
    - [find Module](#find-module)
    - [lookup Module](#lookup-module)
    - [manage Module](#manage-module)
  - [Reference](#reference)
  - [Acknowledgments](#acknowledgments)

## KernelWritePoCs

[Back to Top](#privfu)

[Project](./KernelWritePoCs)

The purpose of this project is to investigate how attackers abuse arbitrary kernel write vulnerability.
All PoCs are written for [HackSys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver).
These PoCs perform to get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges.
Tested on Windows 10 version 1809/1903, but they should work most of Windows 10 theoretically:

| PoC Name | Description |
| :--- | :--- |
| [CreateAssignTokenVariant](./KernelWritePoCs/CreateAssignTokenVariant/CreateAssignTokenVariant.cs) | This PoC performs EoP with `SeCreateTokenPrivilege` and `SeAssignPrimaryTokenPrivilege`. |
| [CreateImpersonateTokenVariant](./KernelWritePoCs/CreateImpersonateTokenVariant/CreateImpersonateTokenVariant.cs) | This PoC performs EoP with `SeCreateTokenPrivilege` and `SeImpersonatePrivilege`. |
| [CreateTokenVariant](./KernelWritePoCs/CreateTokenVariant/CreateTokenVariant.cs) | This PoC performs EoP with `SeCreateTokenPrivilege`. |
| [DebugInjectionVariant](./KernelWritePoCs/DebugInjectionVariant/DebugInjectionVariant.cs) | This PoC performs EoP with `SeDebugPrivilege`. Uses code injection to winlogon.exe at final stage. |
| [DebugUpdateProcVariant](./KernelWritePoCs/DebugUpdateProcVariant/DebugUpdateProcVariant.cs) | This PoC performs EoP with `SeDebugPrivilege`. Creates SYSTEM process from winlogon.exe with `UpdateProcThreadAttribute` API at final stage. |
| [SecondaryLogonVariant](./KernelWritePoCs/SecondaryLogonVariant/SecondaryLogonVariant.cs) | This PoC performs EoP with `SeCreateTokenPrivilege` and `SeImpersonatePrivilege`. Uses secondary logon service at final stage. |


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
C:\dev>SwitchPriv.exe -h

SwitchPriv - Tool to control token privileges.

Usage: SwitchPriv.exe [Options]

        -h, --help      : Displays this help message.
        -e, --enable    : Specifies token privilege to enable. Case insensitive.
        -d, --disable   : Specifies token privilege to disable. Case insensitive.
        -r, --remove    : Specifies token privilege to remove. Case insensitive.
        -p, --pid       : Specifies the target PID. Default specifies PPID.
        -i, --integrity : Specifies integrity level to set.
        -g, --get       : Flag to get available privileges for the target process.
        -s, --system    : Flag to run as "NT AUTHORITY\SYSTEM".
        -l, --list      : Flag to list values for --enable, --disable, --remove and --integrity options.
```

To list values for `--enable`, `--disable`, `--remove` and `--integrity` options, execute this tool with `--list` flag as follows:

```
C:\dev>SwitchPriv.exe -l

Available values for --enable, --disable, and --remove options:
    + CreateToken                    : Specifies SeCreateTokenPrivilege.
    + AssignPrimaryToken             : Specifies SeAssignPrimaryTokenPrivilege.
    + LockMemory                     : Specifies SeLockMemoryPrivilege.
    + IncreaseQuota                  : Specifies SeIncreaseQuotaPrivilege.
    + MachineAccount                 : Specifies SeMachineAccountPrivilege.
    + Tcb                            : Specifies SeTcbPrivilege.
    + Security                       : Specifies SeSecurityPrivilege.
    + TakeOwnership                  : Specifies SeTakeOwnershipPrivilege.
    + LoadDriver                     : Specifies SeLoadDriverPrivilege.

--snip--

Available values for --integrity option:
    + 0 : UNTRUSTED_MANDATORY_LEVEL
    + 1 : LOW_MANDATORY_LEVEL
    + 2 : MEDIUM_MANDATORY_LEVEL
    + 3 : MEDIUM_PLUS_MANDATORY_LEVEL
    + 4 : HIGH_MANDATORY_LEVEL
    + 5 : SYSTEM_MANDATORY_LEVEL
    + 6 : PROTECTED_MANDATORY_LEVEL
    + 7 : SECURE_MANDATORY_LEVEL
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

[*] Integrity Level : MEDIUM_MANDATORY_LEVEL
```

To perform any actions as SYSTEM, set `--system` flag as follows:

```
C:\dev>SwitchPriv.exe -p 1400 -g -s

[>] Trying to get available token privilege(s) for the target process.
    |-> Target PID   : 1400
    |-> Process Name : svchost
[>] Trying to get SYSTEM.
[>] Trying to impersonate thread token.
    |-> Current Thread ID : 4572
[>] Trying to impersonate as smss.exe.
[+] Impersonation is successful.


Privilege Name                             State
========================================== ========
SeAssignPrimaryTokenPrivilege              Disabled
SeLockMemoryPrivilege                      Enabled
SeIncreaseQuotaPrivilege                   Disabled
SeTcbPrivilege                             Enabled
SeSecurityPrivilege                        Disabled
SeTakeOwnershipPrivilege                   Disabled
SeLoadDriverPrivilege                      Disabled
SeSystemProfilePrivilege                   Enabled
SeSystemtimePrivilege                      Disabled
SeProfileSingleProcessPrivilege            Enabled
SeIncreaseBasePriorityPrivilege            Enabled
SeCreatePagefilePrivilege                  Enabled
SeCreatePermanentPrivilege                 Enabled
SeBackupPrivilege                          Disabled
SeRestorePrivilege                         Disabled
SeShutdownPrivilege                        Disabled
SeDebugPrivilege                           Enabled
SeAuditPrivilege                           Enabled
SeSystemEnvironmentPrivilege               Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeManageVolumePrivilege                    Disabled
SeImpersonatePrivilege                     Enabled
SeCreateGlobalPrivilege                    Enabled
SeIncreaseWorkingSetPrivilege              Enabled
SeTimeZonePrivilege                        Enabled
SeCreateSymbolicLinkPrivilege              Enabled
SeDelegateSessionUserImpersonatePrivilege  Enabled

[*] Integrity Level : SYSTEM_MANDATORY_LEVEL
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

[*] Integrity Level : MEDIUM_MANDATORY_LEVEL
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
    |-> Target PID   : 4464
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
    |-> Target PID   : 4464
    |-> Process Name : cmd

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Enabled

[*] Integrity Level : MEDIUM_MANDATORY_LEVEL
```

To remove privilege, use `--remove` option as follows:

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

C:\dev>SwitchPriv.exe -r timezone

[>] Trying to enable SeTimeZonePrivilege.
    |-> Target PID   : 4464
    |-> Process Name : cmd
[+] SeTimeZonePrivilege is removed successfully.


C:\dev>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
```

To enable, disable or remove all available token privileges, specify `all` as the value for `--enable`, `--disable` or `--remove` option:

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
```

If you want to set integrity level, use `--integrity` option as follows:

```
C:\dev>whoami /groups | findstr /i level
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192


C:\dev>SwitchPriv.exe -i 1

[>] Trying to set integrity level.
    |-> Target PID   : 5144
    |-> Process Name : cmd
[>] Trying to set LOW_MANDATORY_LEVEL.
[+] LOW_MANDATORY_LEVEL is set successfully.

C:\dev>whoami /groups | findstr /i level
Mandatory Label\Low Mandatory Level                           Label            S-1-16-4096
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

        -h, --help      : Displays this help message.
        -s, --shell     : Flag for interactive shell.
        -f, --full      : Flag to enable all available privileges.
        -t, --technique : Specifies technique ID. Default ID is 0.
        -c, --command   : Specifies command to execute.
        -d, --domain    : Specifies domain name to add. Default value is "DefaultDomain".
        -u, --username  : Specifies username to add. Default value is "DefaultUser".
        -i, --id        : Specifies RID for virtual domain. Default value is "110".

Available Technique IDs:

        + 0 - Leverages SeCreateTokenPrivilege. Uses only --shell flag, --full flag and --command option.
        + 1 - Leverages virtual logon. This technique creates virtual domain and account as a side effect.
```

For this module, 2 techniques are implemeted.
We can specfy technique with `-t` option.
If you set `0` or don't set value for `-t` option, `TrustExec` will try to create `TrustedInstaller` process with create token technique.
To get interactive shell, set `-s` flag. 

```
C:\dev>TrustExec.exe -m exec -s

[>] Trying to get SYSTEM.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to impersonate as smss.exe.
[+] SeCreateTokenPrivilege is enabled successfully.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[>] Trying to impersonate thread token.
    |-> Current Thread ID : 3360
[+] Impersonation is successful.
[>] Trying to create an elevated primary token.
[+] An elevated primary token is created successfully.
[>] Trying to create a token assigned process.

Microsoft Windows [Version 10.0.19043.1526]
(c) Microsoft Corporation. All rights reserved.

C:\dev>whoami /user

USER INFORMATION
----------------

User Name           SID
=================== ========
nt authority\system S-1-5-18

C:\dev>whoami /groups | findstr /i trusted
NT SERVICE\TrustedInstaller            Well-known group S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464 Enabled by default, Enabled group, Group owner

C:\dev>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeTcbPrivilege                Act as part of the operating system       Enabled
SeDebugPrivilege              Debug programs                            Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

If you set `1` for `-t` option, `TrustExec` will try to create `TrustedInstaller` process with virtual account technique.
This technique creates a virtual accound to impersonate as TrustedInstaller group account as a side effect.
If you don't specify domain name (`-d` option), username (`-u`) and RID (`-i` option), this module create a virtual account `DefaultDomain\DefaultUser`.
Default SID for domain is `S-1-5-110` and for user is `S-1-5-110-110`:

```
C:\dev>TrustExec.exe -m exec -s -t 1

[>] Trying to get SYSTEM.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to impersonate as smss.exe.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[+] SeIncreaseQuotaPrivilege is enabled successfully.
[>] Trying to impersonate thread token.
    |-> Current Thread ID : 2616
[+] Impersonation is successful.
[>] Trying to generate token group information.
[>] Trying to add virtual domain and user.
    |-> Domain   : DefaultDomain (SID : S-1-5-110)
    |-> Username : DefaultUser (SID : S-1-5-110-110)
[+] Added virtual domain and user.
[>] Trying to logon as DefaultDomain\DefaultUser.
[>] Trying to create a token assigned process.

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
[!] Added virtual domain and user are not removed automatically.
    |-> To remove added virtual user SID   : TrustExec.exe -m sid -r -d DefaultDomain -u DefaultUser
    |-> To remove added virtual domain SID : TrustExec.exe -m sid -r -d DefaultDomain
```

You can change domain name and username, use `-d` option and `-u` option.
To change domain RID, use `-i` option as follows:

```
C:\dev>TrustExec.exe -m exec -s -d VirtualDomain -u VirtualAdmin -i 92 -t 1

[>] Trying to get SYSTEM.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to impersonate as smss.exe.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[+] SeIncreaseQuotaPrivilege is enabled successfully.
[>] Trying to impersonate thread token.
    |-> Current Thread ID : 3612
[+] Impersonation is successful.
[>] Trying to generate token group information.
[>] Trying to add virtual domain and user.
    |-> Domain   : VirtualDomain (SID : S-1-5-92)
    |-> Username : VirtualAdmin (SID : S-1-5-92-110)
[+] Added virtual domain and user.
[>] Trying to logon as VirtualDomain\VirtualAdmin.
[>] Trying to create a token assigned process.

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
C:\dev>TrustExec.exe -m exec -c "whoami /user & whoami /priv"

[>] Trying to get SYSTEM.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to impersonate as smss.exe.
[+] SeCreateTokenPrivilege is enabled successfully.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[>] Trying to impersonate thread token.
    |-> Current Thread ID : 1464
[+] Impersonation is successful.
[>] Trying to create an elevated primary token.
[+] An elevated primary token is created successfully.
[>] Trying to create a token assigned process.


USER INFORMATION
----------------

User Name           SID
=================== ========
nt authority\system S-1-5-18

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeTcbPrivilege                Act as part of the operating system       Enabled
SeDebugPrivilege              Debug programs                            Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled

[>] Exit.
```

If you want to enable all available privileges, set `-f` flag as follows:

```
C:\dev>TrustExec.exe -m exec -c "whoami /priv" -f

[>] Trying to get SYSTEM.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to impersonate as smss.exe.
[+] SeCreateTokenPrivilege is enabled successfully.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[>] Trying to impersonate thread token.
    |-> Current Thread ID : 2526
[+] Impersonation is successful.
[>] Trying to create an elevated primary token.
[+] An elevated primary token is created successfully.
[>] Trying to create a token assigned process.


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

[>] Exit.
```

Added domain and username by virtual account technique are not removed automatically.
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

[*] Result:
    |-> Account Name : nt authority\system
    |-> SID          : S-1-5-18
    |-> Account Type : SidTypeWellKnownGroup
```

If you want to lookup SID from domain name, specify domain name with `-d` option as follows:

```
C:\dev>TrustExec.exe -m sid -l -d contoso

[*] Result:
    |-> Account Name : contoso
    |-> SID          : S-1-5-21-3654360273-254804765-2004310818
    |-> Account Type : SidTypeDomain
```

If you want to lookup SID from domain name and username, specify domain name with `-d` option and username with `-u` option as follows:

```
C:\dev>TrustExec.exe -m sid -l -d contoso -u david

[*] Result:
    |-> Account Name : contoso\david
    |-> SID          : S-1-5-21-3654360273-254804765-2004310818-1104
    |-> Account Type : SidTypeUser
```

To remove virutal account, set `-r` flag.
Domain name to remove is specified with `-d` option, username is specified with `-u` option:

```
C:\dev>TrustExec.exe -m sid -r -d defaultdomain -u defaultuser

[>] Trying to get SYSTEM.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to impersonate as smss.exe.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[+] SeIncreaseQuotaPrivilege is enabled successfully.
[>] Trying to impersonate thread token.
    |-> Current Thread ID : 2568
[+] Impersonation is successful.
[>] Trying to remove SID.
    |-> Domain   : defaultdomain
    |-> Username : defaultuser
[*] SID : S-1-5-110-110.
[+] Requested SID is removed successfully.


C:\dev>TrustExec.exe -m sid -r -d defaultdomain

[>] Trying to get SYSTEM.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to impersonate as smss.exe.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[+] SeIncreaseQuotaPrivilege is enabled successfully.
[>] Trying to impersonate thread token.
    |-> Current Thread ID : 4696
[+] Impersonation is successful.
[>] Trying to remove SID.
    |-> Domain   : defaultdomain
[*] SID : S-1-5-110.
[+] Requested SID is removed successfully.
```

> __WARNING__ Deleted SIDs may appear to remain until rebooting the OS.


If you want add domain or user SID, set `-a` flag as follows:

```
C:\dev>TrustExec.exe -m sid -a -d virtualworld -u virtualadmin -i 97

[>] Trying to get SYSTEM.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to impersonate as smss.exe.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[+] SeIncreaseQuotaPrivilege is enabled successfully.
[>] Trying to impersonate thread token.
    |-> Current Thread ID : 3628
[+] Impersonation is successful.
[>] Trying to add virtual domain and user.
    |-> Domain   : virtualworld (SID : S-1-5-97)
    |-> Username : virtualadmin (SID : S-1-5-97-110)
[+] Added virtual domain and user.

C:\dev>TrustExec.exe -m sid -l -s S-1-5-97

[*] Result : virtualworld (SID : S-1-5-97)


C:\dev>TrustExec.exe -m sid -l -s S-1-5-97-110

[*] Result : virtualworld\virtualadmin (SID : S-1-5-97-110)
```


## UserRightsUtil

[Back to Top](#privfu)

[Project](./UserRightsUtil)

This tool is to manage user right without `secpol.msc`.
Commands other than `lookup` require administrator privileges:

```
C:\dev>UserRightsUtil.exe

UserRightsUtil - User rights management utility.

Usage: UserRightsUtil.exe [Options]

        -h, --help   : Displays this help message.
        -m, --module : Specifies module name.

Available Modules:

        + enum   - Enumerate user rights for specific account.
        + find   - Find accounts have a specific user right.
        + lookup - Lookup account's SID.
        + manage - Grant or revoke user rights.

[*] To see help for each modules, specify "-m <Module> -h" as arguments.

[!] -m option is required.
```

### enum Module

To enumerate user rights for a specific account, use `enum` command with `-u` and ~d~ opitons or `-s` option as follows:

```
C:\dev>UserRightsUtil.exe -m enum -d contoso -u jeff

[>] Trying to enumerate user rights.
    |-> Username : CONTOSO\jeff
    |-> SID      : S-1-5-21-3654360273-254804765-2004310818-1105
[+] Got 7 user right(s).
    |-> SeChangeNotifyPrivilege
    |-> SeIncreaseWorkingSetPrivilege
    |-> SeShutdownPrivilege
    |-> SeUndockPrivilege
    |-> SeTimeZonePrivilege
    |-> SeInteractiveLogonRight
    |-> SeNetworkLogonRight
[*] Done.


C:\dev>UserRightsUtil.exe -m enum -s S-1-5-21-3654360273-254804765-2004310818-1105

[>] Trying to enumerate user rights.
    |-> Username : CONTOSO\jeff
    |-> SID      : S-1-5-21-3654360273-254804765-2004310818-1105
[+] Got 7 user right(s).
    |-> SeChangeNotifyPrivilege
    |-> SeIncreaseWorkingSetPrivilege
    |-> SeShutdownPrivilege
    |-> SeUndockPrivilege
    |-> SeTimeZonePrivilege
    |-> SeInteractiveLogonRight
    |-> SeNetworkLogonRight
[*] Done.
```

If you don't specify domain name with `-d` option, use local computer name as domain name:

```
C:\dev>hostname
CL01

C:\dev>UserRightsUtil.exe -m enum -u guest

[>] Trying to enumerate user rights.
    |-> Username : CL01\Guest
    |-> SID      : S-1-5-21-2659926013-4203293582-4033841475-501
[+] Got 3 user right(s).
    |-> SeInteractiveLogonRight
    |-> SeDenyInteractiveLogonRight
    |-> SeDenyNetworkLogonRight
[*] Done.
```

### find Module

This command is to find users who have a specific right.
For example, if you want to find users have `SeDebugPrivilege`, execute as follows:

```
C:\dev>UserRightsUtil.exe -m find -r debug

[>] Trying to find users with SeDebugPrivilege.
[+] Found 1 user(s).
    |-> BUILTIN\Administrators (SID : S-1-5-32-544, Type : SidTypeAlias)
[*] Done.
```

To list available value for `-r` option, use `-l` option:

```
C:\dev>UserRightsUtil.exe -m find -l

Available values for --right option:
        + TrustedCredManAccess           : Specfies SeTrustedCredManAccessPrivilege.
        + NetworkLogon                   : Specfies SeNetworkLogonRight.
        + Tcb                            : Specfies SeTcbPrivilege.
        + MachineAccount                 : Specfies SeMachineAccountPrivilege.
        + IncreaseQuota                  : Specfies SeIncreaseQuotaPrivilege.
        + InteractiveLogon               : Specfies SeInteractiveLogonRight.
        + RemoteInteractiveLogon         : Specfies SeRemoteInteractiveLogonRight.
        + Backup                         : Specfies SeBackupPrivilege.

--snip--
```


### lookup Module

This command is to lookup account SID as follows:

```
C:\dev>UserRightsUtil.exe -m lookup -d contoso -u david

[*] Result:
    |-> Account Name : CONTOSO\david
    |-> SID          : S-1-5-21-3654360273-254804765-2004310818-1104
    |-> Account Type : SidTypeUser


C:\dev>UserRightsUtil.exe -m lookup -s S-1-5-21-3654360273-254804765-2004310818-500

[*] Result:
    |-> Account Name : CONTOSO\Administrator
    |-> SID          : S-1-5-21-3654360273-254804765-2004310818-500
    |-> Account Type : SidTypeUser


C:\dev>UserRightsUtil.exe -m lookup -d contoso -u "domain admins"

[*] Result:
    |-> Account Name : CONTOSO\Domain Admins
    |-> SID          : S-1-5-21-3654360273-254804765-2004310818-512
    |-> Account Type : SidTypeGroup
```

If you don't specify domain name with `-d` option, use local computer name as domain name:

```
C:\dev>hostname
CL01

C:\dev>UserRightsUtil.exe -m lookup -u admin

[*] Result:
    |-> Account Name : CL01\admin
    |-> SID          : S-1-5-21-2659926013-4203293582-4033841475-500
    |-> Account Type : SidTypeUser
```

### manage Module

This command is to grant or revoke user rights for a specific user account.
To grant user right, specify a user right as the value for `-g` option:

```
C:\dev>UserRightsUtil.exe -m find -r tcb

[>] Trying to find users with SeTcbPrivilege.
[-] No users.
[*] Done.


C:\dev>UserRightsUtil.exe -m manage -g tcb -d contoso -u administrator

[>] Target account information:
    |-> Username : CONTOSO\Administrator
    |-> SID      : S-1-5-21-3654360273-254804765-2004310818-500
[>] Trying to grant SeTcbPrivilege.
[+] SeTcbPrivilege is granted successfully.

C:\dev>UserRightsUtil.exe -m find -r tcb

[>] Trying to find users with SeTcbPrivilege.
[+] Found 1 user(s).
    |-> CONTOSO\Administrator (SID : S-1-5-21-3654360273-254804765-2004310818-500, Type : SidTypeUser)
[*] Done.
```

To revoke user right, specify a user right as the value for `-r` option:

```
C:\dev>UserRightsUtil.exe -m find -r tcb

[>] Trying to find users with SeTcbPrivilege.
[+] Found 1 user(s).
    |-> CONTOSO\Administrator (SID : S-1-5-21-3654360273-254804765-2004310818-500, Type : SidTypeUser)
[*] Done.


C:\dev>UserRightsUtil.exe -m manage -r tcb -d contoso -u administrator

[>] Target account information:
    |-> Username : CONTOSO\Administrator
    |-> SID      : S-1-5-21-3654360273-254804765-2004310818-500
[>] Trying to revoke SeTcbPrivilege
[+] SeTcbPrivilege is revoked successfully.

C:\de>UserRightsUtil.exe -m find -r tcb

[>] Trying to find users with SeTcbPrivilege.
[-] No users.
[*] Done.
```

To list available value for `-g` or `-r` option, use `-l` option:

```
C:\dev>UserRightsUtil.exe -m manage -l

Available values for --grant and --revoke options:
        + TrustedCredManAccess           : Specfies SeTrustedCredManAccessPrivilege.
        + NetworkLogon                   : Specfies SeNetworkLogonRight.
        + Tcb                            : Specfies SeTcbPrivilege.
        + MachineAccount                 : Specfies SeMachineAccountPrivilege.
        + IncreaseQuota                  : Specfies SeIncreaseQuotaPrivilege.
        + InteractiveLogon               : Specfies SeInteractiveLogonRight.
        + RemoteInteractiveLogon         : Specfies SeRemoteInteractiveLogonRight.
        + Backup                         : Specfies SeBackupPrivilege.

--snip--
```


## Reference

[Back to Top](#privfu)

- [Priv2Admin](https://github.com/gtworek/Priv2Admin) and [PSBits](https://github.com/gtworek/PSBits) by [Grzegorz Tworek](https://twitter.com/0gtweet)
- [Abusing Token Privileges For LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) by [Bryan Alexander](https://twitter.com/dronesec) and [Steve Breen](https://twitter.com/breenmachine)
- [whoami /priv](https://github.com/decoder-it/whoami-priv-Hackinparis2019) by [Andrea Pierini](https://twitter.com/decoder_it)
- [HackSys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver) by [Ashfaq Ansari](https://twitter.com/hacksysteam)


## Acknowledgments

[Back to Top](#privfu)

Thanks for your advices about WinDbg extension programming:

- Pavel Yosifovich ([@zodiacon](https://twitter.com/zodiacon)) 

Thanks for your notable research:

- Grzegorz Tworek ([@0gtweet](https://twitter.com/0gtweet))
- Bryan Alexander ([@dronesec](https://twitter.com/dronesec))
- Steve Breen ([@breenmachine](https://twitter.com/breenmachine))
- Andrea Pierini ([@decoder_it](https://twitter.com/decoder_it))

Thanks for your sample kernel driver release:

- Ashfaq Ansari ([@HackSysTeam](https://twitter.com/hacksysteam))
