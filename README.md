# PrivFu
Kernel mode WinDbg extension and PoCs for testing how token privileges work.

There are notable repository and articles about token privilege abuse such [Grzegorz Tworek](https://twitter.com/0gtweet)'s [Priv2Admin](https://github.com/gtworek/Priv2Admin).
Codes in this repository are intended to help investigate how token privileges work.


## Table Of Contents

- [PrivFu](#privfu)
  - [PrivEditor](#priveditor)
    - [!getps Command](#!getps-command)
    - [!getpriv Command](#!getpriv-command)
    - [!addpriv Command](#!addpriv-command)
    - [!rmpriv Command](#!rmpriv-command)
    - [!enablepriv Command](#!enablepriv-command)
    - [!disablepriv Command](#!disablepriv-command)
    - [!enableall Command](#!enableall)
    - [!disableall Command](#!disableall)
  - [PrivilegedOperations](#privileged-operations)
  - [Reference](#reference)
  - [Acknowledgments](#acknowledgments)

## PrivEditor
PrivEditor is kernel mode WinDbg extension to manipulate token privilege of specific process.
This extension makes it easy to configure the token privilege you want to investigate.

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


### !getps Command
This command is to list processes in your target system.

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
====== =================== ======================== ============
     0 0xfffff801`3a633630      0x00000000`00000000 System Idle Process
     4 0xffffe588`db068380      0xffffa68a`fd007a40 System
     8 0xffffe588`e0833440      0xffffa68b`016db7b0 vmtoolsd.exe
    88 0xffffe588`db0ea080      0xffffa68a`fd00d080 Registry
   312 0xffffe588`de396400      0xffffa68a`fd0aa990 smss.exe
   348 0xffffe588`db0b4080      0xffffa68b`01fc4770 svchost.exe
   380 0xffffe588`df5c73c0      0xffffa68b`00a640a0 svchost.exe
   396 0xffffe588`de4f3140      0xffffa68a`fda5a630 csrss.exe
   464 0xffffe588`df5be340      0xffffa68b`00a14a40 svchost.exe

--snip--
```

If you want to know specific processes, set string filter as follows.
The filter works with forward matching and case insensitive.

```
0: kd> !getps micro

   PID        nt!_EPROCESS nt!_SEP_TOKEN_PRIVILEGES Process Name
====== =================== ======================== ============
  4456 0xffffe588`e04cd080      0xffffa68b`020617b0 MicrosoftEdge.exe
  4912 0xffffe588`e06832c0      0xffffa68b`02607930 MicrosoftEdgeCP.exe
  4944 0xffffe588`e06ad080      0xffffa68b`0255b2c0 MicrosoftEdgeSH.exe
```


### !getriv Command
This command is to list token privileges of a specific process.

```
0: kd> !getpriv /?

!getpriv - List privileges of a process.

Usage : !getpriv <PID>

    PID : Specifies target process ID.
```

To use this command, you need to set a target process ID in decimal format as follows:

```
0: kd> !getpriv 5328

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Disabled

[*] PID                      : 5328
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffe588`e043b480
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffa68b`029ab7f0
```


### !addpriv Command
This command is to add token privilege(s) to a specific process.

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

If you want to set SeDebugPrivilege to a specific process, set a target process ID for the first argument and shorten privilege name for second argument as follows:

```
0: kd> !getpriv 6488

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeDebugPrivilege                           Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Disabled

[*] PID                      : 6488
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd507`ab522080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffb708`d72697b0
```

The privilege name argument is case insensitive.

If you want to add all token privileges at a time, set `all` as the privilege name argument:

```
0: kd> !addpriv 6488 all

[>] Trying to add the requested privilege(s).
[*] Completed.

0: kd> !getpriv 6488

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


### !rmpriv Command
This command is to remove token privilege(s) from a specific process.

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
0: kd> !getpriv 6792

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Disabled

[*] PID                      : 6792
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd507`ab755080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffb708`d69c2930

0: kd> !rmpriv 6792 changenotify

[>] Trying to delete the requested privilege(s).
[*] Completed.

0: kd> !getpriv 6792

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Disabled

[*] PID                      : 6792
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd507`ab755080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffb708`d69c2930
```

As `!addpriv` command, you can remove all token privileges at a time by setting all as the privilege name argument:

```
0: kd> !rmpriv 6792 all

[>] Trying to delete the requested privilege(s).
[*] Completed.

0: kd> !getpriv 6792

Privilege Name                             State
========================================== ========

[*] PID                      : 6792
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd507`ab755080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffb708`d69c2930
```


### !enablepriv Command
This command is to enable token privilege(s) of a specific process.

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

The first argument is for process ID, and the second is for token privilege name.

```
0: kd> !getpriv 3792

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Disabled

[*] PID                      : 3792
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd507`aaed9080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffb708`d72ab8a0

0: kd> !enablepriv 3792 timezone

[>] Trying to enable the requested privilege(s).
[*] Completed.

0: kd> !getpriv 3792

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Enabled

[*] PID                      : 3792
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd507`aaed9080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffb708`d72ab8a0
```

If you tried to enable privilege(s), not added yet, this command adds it automatically.

```
0: kd> !getpriv 3792

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Enabled

[*] PID                      : 3792
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd507`aaed9080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffb708`d72ab8a0

0: kd> !enablepriv 3792 debug

[*] Requested privilege is not present.
[>] Adding the requested privilege(s).
[>] Trying to enable the requested privilege(s).
[*] Completed.

0: kd> !getpriv 3792

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeDebugPrivilege                           Enabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled
SeTimeZonePrivilege                        Enabled

[*] PID                      : 3792
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd507`aaed9080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffb708`d72ab8a0
```


### !disablepriv Command
This command is to disable token privilege(s) of a specific process.

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

To use this command, set a target process ID for the first argument and token privilege name for the second argument.

```
0: kd> !getpriv 3792

Privilege Name                             State
========================================== ========
SeShutdownPrivilege                        Disabled
SeChangeNotifyPrivilege                    Enabled
SeUndockPrivilege                          Disabled
SeIncreaseWorkingSetPrivilege              Disabled

[*] PID                      : 3792
[*] Process Name             : cmd.exe
[*] nt!_EPROCESS             : 0xffffd507`aaed9080
[*] nt!_SEP_TOKEN_PRIVILEGES : 0xffffb708`d72ab8a0

0: kd> !disablepriv 3792 changenotify

[>] Trying to disable the requested privilege(s).
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


### !enableall Command
This command is to enable all token privilege(s) available for a specific process.

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


### !disableall Command
This command is to disable all token privilege(s) for a specific process.

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
This project is PoCs for sensitive token privileges such SeDebugPrivilege.
Currently, released PoCs for a part of them.

| Program Name | Description |
| :--- | :--- |
| [SeCreateTokenPrivilegePoC](./PrivilegedOperations/SeCreateTokenPrivilegePoC) | This PoC creates a elevated token by SeCreateTokenPrivilege. |
| [SeRestorePrivilegePoC](./PrivilegedOperations/SeRestorePrivilegePoC) | This PoC opens a handle to privileged registry key (`HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice\Parameters`) with `REG_OPTION_BACKUP_RESTORE` flag by SeRestorePrivilege. |
| [SeDebugPrivilegePoC](./PrivilegedOperations/SeDebugPrivilegePoC) | This PoC opens a handle to winlogon.exe by SeDebugPrivilege. |


## Reference
- [Priv2Admin](https://github.com/gtworek/Priv2Admin) by [Grzegorz Tworek](https://twitter.com/0gtweet)
- [Abusing Token Privileges For LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) by [Bryan Alexander](https://twitter.com/dronesec) and [Steve Breen](https://twitter.com/breenmachine)
- [whoami /priv](https://github.com/decoder-it/whoami-priv-Hackinparis2019) by [Andrea Pierini](https://twitter.com/decoder_it)

## Acknowledgments
Thanks for your advices about WinDbg extension programming:

- Pavel Yosifovich ([@zodiacon](https://twitter.com/zodiacon)) 

Thanks for your notable research:

- Grzegorz Tworek ([@0gtweet](https://twitter.com/0gtweet))
- Bryan Alexander ([@dronesec](https://twitter.com/dronesec))
- Steve Breen ([@breenmachine](https://twitter.com/breenmachine))
- Andrea Pierini ([@decoder_it](https://twitter.com/decoder_it))