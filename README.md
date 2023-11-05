# PrivFu
Kernel mode WinDbg extension and PoCs for testing how token privileges work.

There are notable repository and articles about token privilege abuse such [Grzegorz Tworek](https://twitter.com/0gtweet)'s [Priv2Admin](https://github.com/gtworek/Priv2Admin).
Codes in this repository are intended to help investigate how token privileges work.


## Table Of Contents

- [PrivFu](#privfu)
  - [ArtsOfGetSystem](#ArtsOfGetSystem)
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
  - [S4uDelegator](#s4udelegator)
  - [SwitchPriv](#switchpriv)
  - [TokenDump](#tokendump)
  - [TrustExec](#trustexec)
  - [UserRightsUtil](#userrightsutil)
  - [Reference](#reference)
  - [Acknowledgments](#acknowledgments)

## ArtsOfGetSystem

[Back to Top](#privfu)

[Project](./ArtsOfGetSystem)

This project covers how to get system privileges from high integrity level shell.
See [README.md](./ArtsOfGetSystem/README.md) for details.


## KernelWritePoCs

[Back to Top](#privfu)

[Project](./KernelWritePoCs)

The purpose of this project is to investigate how attackers abuse arbitrary kernel write vulnerability.
All PoCs are written for [HackSys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver).
Most of these PoCs perform to get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges.
Tested on Windows 10 version 1809/1903, but they should work most of Windows 10 theoretically:

| PoC Name | Description |
| :--- | :--- |
| [CreateAssignTokenVariant](./KernelWritePoCs/CreateAssignTokenVariant/CreateAssignTokenVariant.cs) | This PoC performs EoP with `SeCreateTokenPrivilege` and `SeAssignPrimaryTokenPrivilege`. |
| [CreateImpersonateTokenVariant](./KernelWritePoCs/CreateImpersonateTokenVariant/CreateImpersonateTokenVariant.cs) | This PoC performs EoP with `SeCreateTokenPrivilege` and `SeImpersonatePrivilege`. |
| [CreateTokenVariant](./KernelWritePoCs/CreateTokenVariant/CreateTokenVariant.cs) | This PoC performs EoP with `SeCreateTokenPrivilege`. |
| [DebugInjectionVariant](./KernelWritePoCs/DebugInjectionVariant/DebugInjectionVariant.cs) | This PoC performs EoP with `SeDebugPrivilege`. Uses code injection to winlogon.exe at final stage. |
| [DebugUpdateProcVariant](./KernelWritePoCs/DebugUpdateProcVariant/DebugUpdateProcVariant.cs) | This PoC performs EoP with `SeDebugPrivilege`. Creates SYSTEM process from winlogon.exe with `UpdateProcThreadAttribute` API at final stage. |
| [RestoreServiceModificationVariant](./KernelWritePoCs/RestoreServiceModificationVariant/RestoreServiceModificationVariant.cs) | This PoC performs EoP with `SeRestorePrivilege`. Use [HijackShellLib](./KernelWritePoCs/HijackShellLib) with this PoC. |
| [SecondaryLogonVariant](./KernelWritePoCs/SecondaryLogonVariant/SecondaryLogonVariant.cs) | This PoC performs EoP with `SeCreateTokenPrivilege` and `SeImpersonatePrivilege`. Uses secondary logon service at final stage. |
| [TakeOwnershipServiceModificationVariant](./KernelWritePoCs/TakeOwnershipServiceModificationVariant/TakeOwnershipServiceModificationVariant.cs) | This PoC performs EoP with `SeTakeOwnershipPrivilege`. Use [HijackShellLib](./KernelWritePoCs/HijackShellLib) with this PoC. |
| [TcbS4uAssignTokenVariant](./KernelWritePoCs/TcbS4uAssignTokenVariant/TcbS4uAssignTokenVariant.cs) | This PoC performs EoP with `SeTcbPrivilege`. Get System mandatory level shell from medium mandatory level. |
| [TcbS4uImpersonationVariant](./KernelWritePoCs/TcbS4uImpersonationVariant/TcbS4uImpersonationVariant.cs) | This PoC performs EoP with `SeTcbPrivilege`. Performs thread impersonation with S4U logon. Not get high or system integrity level. |


## PrivEditor

[Back to Top](#privfu)

[Project](./PrivEditor)

> __Warning__
> 
> In some environment, Debug build does not work.
> Release build is preferred.

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
       0 0xfffff805`81233630      0x00000000`00000000 Idle
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
[*] Done.

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
[*] Done.

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
[*] Done.

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
[*] Done.

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
[*] Done.

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
[*] Done.

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
[*] Done.

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
[*] Done.

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
[*] Done.

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

This project is PoCs for sensitive token privileges such `SeDebugPrivilege`.
Currently, released PoCs for a part of them.

| Program Name | Description |
| :--- | :--- |
| [SeAuditPrivilegePoC](./PrivilegedOperations/SeAuditPrivilegePoC) | This PoC tries to create new security event(s) by `SeAuditPrivilegePoC`. `SeAuditPrivilege` does not require high integrity level, but this PoC requires administrative privileges at the first execution to install new event source. Additionally, to confirm the result, this PoC may require modification of local security policy setting. |
| [SeBackupPrivilegePoC](./PrivilegedOperations/SeBackupPrivilegePoC) | This PoC tries to dump `HKLM\SAM` by `SeBackupPrivilege`. |
| [SeCreatePagefilePrivilegePoC](./PrivilegedOperations/SeCreatePagefilePrivilegePoC) | This PoC tries to set pagefile option to specific values by `SeCreatePagefilePrivilege`. |
| [SeCreateTokenPrivilegePoC](./PrivilegedOperations/SeCreateTokenPrivilegePoC) | This PoC tries to create a elevated token by `SeCreateTokenPrivilege`. |
| [SeDebugPrivilegePoC](./PrivilegedOperations/SeDebugPrivilegePoC) | This PoC tries to open a handle to winlogon.exe by `SeDebugPrivilege`. |
| [SeRestorePrivilegePoC](./PrivilegedOperations/SeRestorePrivilegePoC) | This PoC tries to write test file in `C:\Windows\System32\` by `SeRestorePrivilege`. |
| [SeSecurityPrivilegePoC](./PrivilegedOperations/SeSecurityPrivilegePoC) | This PoC tries to read the latest security event by `SeSecurityPrivilege`. |
| [SeShutdownPrivilegePoC](./PrivilegedOperations/SeShutdownPrivilegePoC) | This PoC tries to cause BSOD by `SeShutdownPrivilege`. |
| [SeSystemEnvironmentPrivilegePoC](./PrivilegedOperations/SeSystemEnvironmentPrivilegePoC) | This PoC tries to enumerate system environment by `SeSystemEnvironmentPrivilege`. Works for UEFI based system only. Due to OS functionality, this PoC does not work for OSes earlier Windows 10 Build 1809. |
| [SeTakeOwnershipPrivilegePoC](./PrivilegedOperations/SeTakeOwnershipPrivilegePoC) | This PoC tries to change the owner of `HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice` to the caller user account by `SeTakeOwnershipPrivilege`. |
| [SeTcbPrivilegePoC](./PrivilegedOperations/SeTcbPrivilegePoC) | This PoC tries to perform S4U Logon to be `Builtin\Backup Operators` by `SeTcbPrivilege`. |
| [SeTrustedCredManAccessPrivilegePoC](./PrivilegedOperations/SeTrustedCredManAccessPrivilegePoC) | This PoC tries to access DPAPI blob by `SeTrustedCredManAccessPrivilege`. |

## S4uDelegator

[Back to Top](#privfu)

[Project](./S4uDelegator)

This tool is to perform S4U logon with SeTcbPrivilege.
To perform S4U logon with this tool, administrative privileges are required.

```
PS C:\Tools> .\S4uDelegator.exe -h

S4uDelegator - Tool for S4U Logon.

Usage: S4uDelegator.exe [Options]

        -h, --help    : Displays this help message.
        -l, --lookup  : Flag to lookup account SID.
        -x, --execute : Flag to execute command.
        -c, --command : Specifies command to execute. Default is cmd.exe.
        -d, --domain  : Specifies domain name to lookup or S4U logon.
        -e, --extra   : Specifies group SIDs you want to add for S4U logon with comma separation.
        -n, --name    : Specifies account name to lookup or S4U logon.
        -s, --sid     : Specifies SID to lookup.
```

To use this tool, `-l` or `-x` flag must be specified.
`-l` flag is for looking up account information as follows:

```
PS C:\Tools> .\S4uDelegator.exe -l -d contoso -n "domain admins"

[*] Account Name : CONTOSO\Domain Admins
[*] SID          : S-1-5-21-3654360273-254804765-2004310818-512
[*] Account Type : Group

PS C:\Tools> .\S4uDelegator.exe -l -s S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736

[*] Account Name : NT SERVICE\WinDefend
[*] SID          : S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736
[*] Account Type : WellKnownGroup
```

To execute command with S4U logon, set `-x` flag, and specify account name or SID as follows.
Command to execute can be specified with `-c` option (default is `cmd.exe`):

```
PS C:\Tools> whoami /user

USER INFORMATION
----------------

User Name    SID
============ =============================================
contoso\jeff S-1-5-21-3654360273-254804765-2004310818-1105
PS C:\Tools> .\S4uDelegator.exe -x -d . -n admin

[*] S4U logon target information:
    [*] Account : CL01\admin
    [*] SID     : S-1-5-21-2659926013-4203293582-4033841475-500
    [*] UPN     : (Null)
    [*] Type    : User
[>] Trying to get SYSTEM.
[+] Got SYSTEM privileges.
[>] Trying to S4U logon.
[+] S4U logon is successful.
[>] Trying to create a token assigned process.
Microsoft Windows [Version 10.0.18362.175]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Tools>whoami /user

USER INFORMATION
----------------

User Name  SID
========== =============================================
cl01\admin S-1-5-21-2659926013-4203293582-4033841475-500
```

If you want to add extra group information, set group SIDs with comma separated value with `-e` option as follows:

```
PS C:\Tools> whoami /user

USER INFORMATION
----------------

User Name     SID
============= =============================================
contoso\david S-1-5-21-3654360273-254804765-2004310818-1104
PS C:\Tools> .\S4uDelegator.exe -x -d contoso -n jeff -e S-1-5-32-544,S-1-5-20 -c powershell

[*] S4U logon target information:
    [*] Account : CONTOSO\jeff
    [*] SID     : S-1-5-21-3654360273-254804765-2004310818-1105
    [*] UPN     : jeff@contoso.local
    [*] Type    : User
[>] Verifying extra group SID(s).
[*] BUILTIN\Administrators (SID : S-1-5-32-544) will be added as a group.
[*] NT AUTHORITY\NETWORK SERVICE (SID : S-1-5-20) will be added as a group.
[>] Trying to get SYSTEM.
[+] Got SYSTEM privileges.
[>] Trying to S4U logon.
[+] S4U logon is successful.
[>] Trying to create a token assigned process.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Tools> whoami /user

USER INFORMATION
----------------

User Name    SID
============ =============================================
contoso\jeff S-1-5-21-3654360273-254804765-2004310818-1105
PS C:\Tools> whoami /groups                                                                                             
GROUP INFORMATION
-----------------

Group Name                             Type             SID                                           Attributes        
====================================== ================ ============================================= ==================================================
Everyone                               Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                 Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK SERVICE           Well-known group S-1-5-20                                      Mandatory group, Enabled by default, Enabled group
CONTOSO\ServerAdmins                   Group            S-1-5-21-3654360273-254804765-2004310818-1103 Mandatory group, Enabled by default, Enabled group
Service asserted identity              Well-known group S-1-18-2                                      Mandatory group, Enabled by default, Enabled group
Mandatory Label\System Mandatory Level Label            S-1-16-16384
```

> __WARNING__
>
> If you try S4U logon with unprivileged account for target machine, you will get error `0xC0000142` (`STATUS_DLL_INIT_FAILED`) and command cannot be executed.
> To avoid this problem, add privileged groups as extra groups with `-e` option.
> 
> Additionaly, some account cannot be specified as extra group (e.g. `NT SERVICE\TrustedInstaller`) for S4U logon.
> If you set such group accounts as extra group, S4U logon will be failed with error `0x00000005` (`ERROR_ACCESS_DENIED`)


## SwitchPriv

[Back to Top](#privfu)

[Project](./SwitchPriv)

This tool is to enable or disable specific token privileges for a process:

```
PS C:\Dev> .\SwitchPriv.exe -h

SwitchPriv - Tool to control token privileges.

Usage: SwitchPriv.exe [Options]

        -h, --help      : Displays this help message.
        -d, --disable   : Specifies token privilege to disable or "all".
        -e, --enable    : Specifies token privilege to enable or "all".
        -f, --filter    : Specifies token privilege you want to remain.
        -i, --integrity : Specifies integrity level to set in decimal value.
        -p, --pid       : Specifies the target PID. Default specifies PPID.
        -r, --remove    : Specifies token privilege to remove or "all".
        -s, --search    : Specifies token privilege to search.
        -g, --get       : Flag to get available privileges for the target process.
        -l, --list      : Flag to list values for --integrity options.
        -S, --system    : Flag to run as "NT AUTHORITY\SYSTEM".
```

To list values for `--integrity` option, execute with `--list` flag as follows:

```
PS C:\Dev> .\SwitchPriv.exe -l

Available values for --integrity option:

    * 0 : UNTRUSTED_MANDATORY_LEVEL
    * 1 : LOW_MANDATORY_LEVEL
    * 2 : MEDIUM_MANDATORY_LEVEL
    * 3 : MEDIUM_PLUS_MANDATORY_LEVEL
    * 4 : HIGH_MANDATORY_LEVEL
    * 5 : SYSTEM_MANDATORY_LEVEL
    * 6 : PROTECTED_MANDATORY_LEVEL
    * 7 : SECURE_MANDATORY_LEVEL

Example :

    * Down a specific process' integrity level to Low.

        PS C:\> .\SwitchPriv.exe -p 4142 -s 1

Protected and Secure level should not be available, but left for research purpose.
```

The target process' PID is specified with `-p` option.
You can list available privileges for the target process with `-g` flag and `-p` option as follows:

```
PS C:\Dev> .\SwitchPriv.exe -p 9408 -g

[>] Trying to get available token privilege(s) for the target process.
    [*] Target PID   : 9408
    [*] Process Name : Notepad
[+] Got 5 token privilege(s).

PRIVILEGES INFORMATION
----------------------

Privilege Name                State
============================= =========================
SeShutdownPrivilege           Disabled
SeChangeNotifyPrivilege       EnabledByDefault, Enabled
SeUndockPrivilege             Disabled
SeIncreaseWorkingSetPrivilege Disabled
SeTimeZonePrivilege           Disabled

[*] Integrity Level : Medium Mandatory Level
[*] Done.
```

When `-p` option is not specified, PID will be parent PID for this tool:

```
PS C:\Dev> .\SwitchPriv.exe -g

[>] Trying to get available token privilege(s) for the target process.
    [*] Target PID   : 6772
    [*] Process Name : powershell
[+] Got 5 token privilege(s).

PRIVILEGES INFORMATION
----------------------

Privilege Name                State
============================= =========================
SeShutdownPrivilege           Disabled
SeChangeNotifyPrivilege       EnabledByDefault, Enabled
SeUndockPrivilege             Disabled
SeIncreaseWorkingSetPrivilege Disabled
SeTimeZonePrivilege           Disabled

[*] Integrity Level : Medium Mandatory Level
[*] Done.
```

Privilege name to control is specfied with any case insensitive strings which can specify a unique privilege name in available privileges for the target process.
For example, to enable `SeUndockPrivilege` for the target process, execute with `--enable` option as follows:

```
PS C:\Dev> .\SwitchPriv.exe -p 9408 -g

[>] Trying to get available token privilege(s) for the target process.
    [*] Target PID   : 9408
    [*] Process Name : Notepad
[+] Got 5 token privilege(s).

PRIVILEGES INFORMATION
----------------------

Privilege Name                State
============================= =========================
SeShutdownPrivilege           Disabled
SeChangeNotifyPrivilege       EnabledByDefault, Enabled
SeUndockPrivilege             Disabled
SeIncreaseWorkingSetPrivilege Disabled
SeTimeZonePrivilege           Disabled

[*] Integrity Level : Medium Mandatory Level
[*] Done.

PS C:\Dev> .\SwitchPriv.exe -p 9408 -e und

[>] Trying to enable a token privilege.
    [*] Target PID   : 9408
    [*] Process Name : Notepad
[+] SeUndockPrivilege is enabled successfully.
[*] Done.

PS C:\Dev> .\SwitchPriv.exe -p 9408 -g

[>] Trying to get available token privilege(s) for the target process.
    [*] Target PID   : 9408
    [*] Process Name : Notepad
[+] Got 5 token privilege(s).

PRIVILEGES INFORMATION
----------------------

Privilege Name                State
============================= =========================
SeShutdownPrivilege           Disabled
SeChangeNotifyPrivilege       EnabledByDefault, Enabled
SeUndockPrivilege             Enabled
SeIncreaseWorkingSetPrivilege Disabled
SeTimeZonePrivilege           Disabled

[*] Integrity Level : Medium Mandatory Level
[*] Done.
```

When you set bogus string which can not specify a unique privilege name, you will get following message:

```
PS C:\Dev> .\SwitchPriv.exe -p 9408 -e se

[>] Trying to enable a token privilege.
    [*] Target PID   : 9408
    [*] Process Name : Notepad
[-] Cannot specify a unique privilege to enable.
    [*] SeShutdownPrivilege
    [*] SeChangeNotifyPrivilege
    [*] SeUndockPrivilege
    [*] SeIncreaseWorkingSetPrivilege
    [*] SeTimeZonePrivilege
[*] Done.
```

For example, to enable SeChangeNotifyPrivilege, execute with `--disable` option as follows:

```
PS C:\Dev> .\SwitchPriv.exe -p 9408 -g

[>] Trying to get available token privilege(s) for the target process.
    [*] Target PID   : 9408
    [*] Process Name : Notepad
[+] Got 5 token privilege(s).

PRIVILEGES INFORMATION
----------------------

Privilege Name                State
============================= =========================
SeShutdownPrivilege           Disabled
SeChangeNotifyPrivilege       EnabledByDefault, Enabled
SeUndockPrivilege             Enabled
SeIncreaseWorkingSetPrivilege Disabled
SeTimeZonePrivilege           Disabled

[*] Integrity Level : Medium Mandatory Level
[*] Done.

PS C:\Dev> .\SwitchPriv.exe -p 9408 -d chan

[>] Trying to disable a token privilege.
    [*] Target PID   : 9408
    [*] Process Name : Notepad
[+] SeChangeNotifyPrivilege is disabled successfully.
[*] Done.

PS C:\Dev> .\SwitchPriv.exe -p 9408 -g

[>] Trying to get available token privilege(s) for the target process.
    [*] Target PID   : 9408
    [*] Process Name : Notepad
[+] Got 5 token privilege(s).

PRIVILEGES INFORMATION
----------------------

Privilege Name                State
============================= ==========================
SeShutdownPrivilege           Disabled
SeChangeNotifyPrivilege       EnabledByDefault, Disabled
SeUndockPrivilege             Enabled
SeIncreaseWorkingSetPrivilege Disabled
SeTimeZonePrivilege           Disabled

[*] Integrity Level : Medium Mandatory Level
[*] Done.
```

To remove privilege, use `--remove` option as follows:

```
PS C:\Dev> .\SwitchPriv.exe -p 9408 -g

[>] Trying to get available token privilege(s) for the target process.
    [*] Target PID   : 9408
    [*] Process Name : Notepad
[+] Got 5 token privilege(s).

PRIVILEGES INFORMATION
----------------------

Privilege Name                State
============================= ==========================
SeShutdownPrivilege           Disabled
SeChangeNotifyPrivilege       EnabledByDefault, Disabled
SeUndockPrivilege             Enabled
SeIncreaseWorkingSetPrivilege Disabled
SeTimeZonePrivilege           Disabled

[*] Integrity Level : Medium Mandatory Level
[*] Done.

PS C:\Dev> .\SwitchPriv.exe -p 9408 -r inc

[>] Trying to remove a token privilege.
    [*] Target PID   : 9408
    [*] Process Name : Notepad
[+] SeIncreaseWorkingSetPrivilege is removed successfully.
[*] Done.

PS C:\Dev> .\SwitchPriv.exe -p 9408 -g

[>] Trying to get available token privilege(s) for the target process.
    [*] Target PID   : 9408
    [*] Process Name : Notepad
[+] Got 4 token privilege(s).

PRIVILEGES INFORMATION
----------------------

Privilege Name          State
======================= ==========================
SeShutdownPrivilege     Disabled
SeChangeNotifyPrivilege EnabledByDefault, Disabled
SeUndockPrivilege       Enabled
SeTimeZonePrivilege     Disabled

[*] Integrity Level : Medium Mandatory Level
[*] Done.
```

If you want to test a specific privilege, you can remove all privileges other than you want to test with `-f` option as follows:

```
PS C:\Dev> .\SwitchPriv.exe -g

[>] Trying to get available token privilege(s) for the target process.
    [*] Target PID   : 4392
    [*] Process Name : powershell
[+] Got 5 token privilege(s).

PRIVILEGES INFORMATION
----------------------

Privilege Name                State
============================= =========================
SeShutdownPrivilege           Enabled
SeChangeNotifyPrivilege       EnabledByDefault, Enabled
SeUndockPrivilege             Enabled
SeIncreaseWorkingSetPrivilege Enabled
SeTimeZonePrivilege           Enabled

[*] Integrity Level : Medium Mandatory Level
[*] Done.

PS C:\Dev> .\SwitchPriv.exe -f tim

[>] Trying to remove all token privileges except one.
    [*] Target PID   : 4392
    [*] Process Name : powershell
[>] Trying to remove all privileges except for SeTimeZonePrivilege.
[+] SeShutdownPrivilege is removed successfully.
[+] SeChangeNotifyPrivilege is removed successfully.
[+] SeUndockPrivilege is removed successfully.
[+] SeIncreaseWorkingSetPrivilege is removed successfully.
[*] Done.

PS C:\Dev> .\SwitchPriv.exe -g

[>] Trying to get available token privilege(s) for the target process.
    [*] Target PID   : 4392
    [*] Process Name : powershell
[+] Got 1 token privilege(s).

PRIVILEGES INFORMATION
----------------------

Privilege Name      State
=================== =======
SeTimeZonePrivilege Enabled

[*] Integrity Level : Medium Mandatory Level
[*] Done.
```

To enable, disable or remove all available token privileges, specify `all` as the value for `--enable`, `--disable` or `--remove` option:

```
PS C:\Dev> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
PS C:\Dev> .\SwitchPriv.exe -e all

[>] Trying to enable all token privileges.
    [*] Target PID   : 6772
    [*] Process Name : powershell
[+] SeShutdownPrivilege is enabled successfully.
[+] SeUndockPrivilege is enabled successfully.
[+] SeIncreaseWorkingSetPrivilege is enabled successfully.
[+] SeTimeZonePrivilege is enabled successfully.
[*] Done.

PS C:\Dev> whoami /priv

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

To find process have a specific privilege, use `-s` option as follows:

```
PS C:\Dev> .\SwitchPriv.exe -s createt

[>] Searching processes have SeCreateTokenPrivilege.
[+] Got 5 process(es).
    [*] Memory Compression (PID : 2548)
    [*] smss (PID : 372)
    [*] lsass (PID : 736)
    [*] csrss (PID : 584)
    [*] csrss (PID : 504)
[*] Access is denied by following 2 process(es).
    [*] System (PID : 4)
    [*] Idle (PID : 0)
[*] Done.


PS C:\Dev> .\SwitchPriv.exe -g -p 2548

[>] Trying to get available token privilege(s) for the target process.
    [*] Target PID   : 2548
    [*] Process Name : Memory Compression
[+] Got 31 token privilege(s).

PRIVILEGES INFORMATION
----------------------

Privilege Name                            State
========================================= =========================
SeCreateTokenPrivilege                    Disabled
SeAssignPrimaryTokenPrivilege             Disabled
SeLockMemoryPrivilege                     EnabledByDefault, Enabled
SeIncreaseQuotaPrivilege                  Disabled
SeTcbPrivilege                            EnabledByDefault, Enabled
SeSecurityPrivilege                       Disabled
SeTakeOwnershipPrivilege                  Disabled
SeLoadDriverPrivilege                     Disabled
SeSystemProfilePrivilege                  EnabledByDefault, Enabled
SeSystemtimePrivilege                     Disabled
SeProfileSingleProcessPrivilege           EnabledByDefault, Enabled
SeIncreaseBasePriorityPrivilege           EnabledByDefault, Enabled
SeCreatePagefilePrivilege                 EnabledByDefault, Enabled
SeCreatePermanentPrivilege                EnabledByDefault, Enabled
SeBackupPrivilege                         Disabled
SeRestorePrivilege                        Disabled
SeShutdownPrivilege                       Disabled
SeDebugPrivilege                          EnabledByDefault, Enabled
SeAuditPrivilege                          EnabledByDefault, Enabled
SeSystemEnvironmentPrivilege              Disabled
SeChangeNotifyPrivilege                   EnabledByDefault, Enabled
SeUndockPrivilege                         Disabled
SeManageVolumePrivilege                   Disabled
SeImpersonatePrivilege                    EnabledByDefault, Enabled
SeCreateGlobalPrivilege                   EnabledByDefault, Enabled
SeTrustedCredManAccessPrivilege           Disabled
SeRelabelPrivilege                        Disabled
SeIncreaseWorkingSetPrivilege             EnabledByDefault, Enabled
SeTimeZonePrivilege                       EnabledByDefault, Enabled
SeCreateSymbolicLinkPrivilege             EnabledByDefault, Enabled
SeDelegateSessionUserImpersonatePrivilege EnabledByDefault, Enabled

[*] Integrity Level : System Mandatory Level
[*] Done.
```

If you want to set integrity level, use `--integrity` option as follows:

```
PS C:\Dev> whoami /groups | findstr /i level
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192

PS C:\Dev> .\SwitchPriv.exe -i 1

[>] Trying to update Integrity Level.
    [*] Target PID   : 3436
    [*] Process Name : powershell
[>] Trying to update Integrity Level to LOW_MANDATORY_LEVEL.
[+] Integrity Level is updated successfully.
[*] Done.

PS C:\Dev> whoami /groups | findstr /i level
Mandatory Label\Low Mandatory Level                           Label            S-1-16-4096
```

To perform any actions as SYSTEM, set `-S` flag as follows (`SeDebugPrivilege` and `SeImpersonatePrivilege` are required):

```
PS C:\Dev> .\SwitchPriv.exe -g -p 2548 -S

[>] Trying to get available token privilege(s) for the target process.
    [*] Target PID   : 2548
    [*] Process Name : Memory Compression
[>] Trying to get SYSTEM.
[+] Got SYSTEM privilege.
[+] Got 31 token privilege(s).

PRIVILEGES INFORMATION
----------------------

Privilege Name                            State
========================================= =========================
SeCreateTokenPrivilege                    Disabled
SeAssignPrimaryTokenPrivilege             Disabled
SeLockMemoryPrivilege                     EnabledByDefault, Enabled
SeIncreaseQuotaPrivilege                  Disabled
SeTcbPrivilege                            EnabledByDefault, Enabled
SeSecurityPrivilege                       Disabled
SeTakeOwnershipPrivilege                  Disabled
SeLoadDriverPrivilege                     Disabled
SeSystemProfilePrivilege                  EnabledByDefault, Enabled
SeSystemtimePrivilege                     Disabled
SeProfileSingleProcessPrivilege           EnabledByDefault, Enabled
SeIncreaseBasePriorityPrivilege           EnabledByDefault, Enabled
SeCreatePagefilePrivilege                 EnabledByDefault, Enabled
SeCreatePermanentPrivilege                EnabledByDefault, Enabled
SeBackupPrivilege                         Disabled
SeRestorePrivilege                        Disabled
SeShutdownPrivilege                       Disabled
SeDebugPrivilege                          EnabledByDefault, Enabled
SeAuditPrivilege                          EnabledByDefault, Enabled
SeSystemEnvironmentPrivilege              Disabled
SeChangeNotifyPrivilege                   EnabledByDefault, Enabled
SeUndockPrivilege                         Disabled
SeManageVolumePrivilege                   Disabled
SeImpersonatePrivilege                    EnabledByDefault, Enabled
SeCreateGlobalPrivilege                   EnabledByDefault, Enabled
SeTrustedCredManAccessPrivilege           Disabled
SeRelabelPrivilege                        Disabled
SeIncreaseWorkingSetPrivilege             EnabledByDefault, Enabled
SeTimeZonePrivilege                       EnabledByDefault, Enabled
SeCreateSymbolicLinkPrivilege             EnabledByDefault, Enabled
SeDelegateSessionUserImpersonatePrivilege EnabledByDefault, Enabled

[*] Integrity Level : System Mandatory Level
[*] Done.
```


## TokenDump

[Back to Top](#privfu)

[Project](./TokenDump)


This tool is a utility to inspect token information:

```
C:\Dev>.\TokenDump.exe -h

TokenDump - Tool to dump processs token information.

Usage: TokenDump.exe [Options]

        -h, --help    : Displays this help message.
        -d, --debug   : Flag to enable SeDebugPrivilege.
        -e, --enum    : Flag to enumerate brief information tokens for processes or handles.
        -T, --thread  : Flag to scan thead tokens. Use with -e option.
        -H, --handle  : Flag to scan token handles. Use with -e option.
        -s, --scan    : Flag to get verbose information for a specific process, thread or handle.
        -a, --account : Specifies account name filter string. Use with -e flag.
        -p, --pid     : Specifies a target PID in decimal format. Use with -s flag, or -e and -H flag.
        -t, --tid     : Specifies a target TID in decimal format. Use with -s flag and -p option.
        -v, --value   : Specifies a token handle value in hex format. Use with -s flag and -p option.
```

To enumerate token for all processes, just set `-e` flag:

```
C:\Dev>.\TokenDump.exe -e

[>] Trying to enumerate process token.

 PID Session Process Name                Token User                   Integrity Restricted AppContainer
==== ======= =========================== ============================ ========= ========== ============
5004       0 svchost.exe                 NT AUTHORITY\SYSTEM          System    False      False
3728       0 conhost.exe                 NT AUTHORITY\SYSTEM          System    False      False

--snip--

6712       0 svchost.exe                 NT AUTHORITY\LOCAL SERVICE   System    False      False
1972       0 svchost.exe                 NT AUTHORITY\SYSTEM          System    False      False

[+] Got 129 token information.
[*] Found 7 account(s).
    [*] NT AUTHORITY\SYSTEM
    [*] dev22h2\user
    [*] NT AUTHORITY\LOCAL SERVICE
    [*] NT AUTHORITY\NETWORK SERVICE
    [*] Font Driver Host\UMFD-0
    [*] Font Driver Host\UMFD-1
    [*] Window Manager\DWM-1
[*] Done.
```

If you want to enable SeDebugPrivilege, set `-d` flag as follows:

```
C:\Dev>.\TokenDump.exe -e -d

[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to enumerate process token.

 PID Session Process Name                Token User                   Integrity Restricted AppContainer
==== ======= =========================== ============================ ========= ========== ============
5004       0 svchost.exe                 NT AUTHORITY\SYSTEM          System    False      False
3728       0 conhost.exe                 NT AUTHORITY\SYSTEM          System    False      False
3740       0 vm3dservice.exe             NT AUTHORITY\SYSTEM          System    False      False

--snip--
```

When set `-H` flag with `-e` flag, TokenDump tries to enumerate Token handles information:

```
C:\Dev>.\TokenDump.exe -e -H -d

[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to enumerate token handles.

[Token Handle(s) - winlogon.exe (PID: 704)]

Handle Session Token User          Integrity Restricted AppContainer Token Type    Impersonation Level
====== ======= =================== ========= ========== ============ ============= ===================
 0x2B0       1 NT AUTHORITY\SYSTEM System    False      False        Primary       Anonymous
 0x2B4       1 NT AUTHORITY\SYSTEM System    False      False        Primary       Anonymous
 0x38C       1 dev22h2\user        Medium    False      False        Primary       Impersonation

--snip--

[Token Handle(s) - svchost.exe (PID: 3272)]

Handle Session Token User                 Integrity Restricted AppContainer Token Type Impersonation Level
====== ======= ========================== ========= ========== ============ ========== ===================
 0x168       0 NT AUTHORITY\LOCAL SERVICE System    False      False        Primary    Anonymous

[+] Got 819 handle(s).
[*] Found 8 account(s).
    [*] NT AUTHORITY\SYSTEM
    [*] dev22h2\user
    [*] Font Driver Host\UMFD-1
    [*] Font Driver Host\UMFD-0
    [*] NT AUTHORITY\NETWORK SERVICE
    [*] Window Manager\DWM-1
    [*] NT AUTHORITY\LOCAL SERVICE
    [*] NT AUTHORITY\ANONYMOUS LOGON
[*] Done.
```

When specified PID with `-p` option, TokenDup enumerate only the specified process handles:

```
C:\Dev>.\TokenDump.exe -e -H -d -p 704

[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to enumerate token handles.

[Token Handle(s) - winlogon.exe (PID: 704)]

Handle Session Token User          Integrity Restricted AppContainer Token Type    Impersonation Level
====== ======= =================== ========= ========== ============ ============= ===================
 0x2B0       1 NT AUTHORITY\SYSTEM System    False      False        Primary       Anonymous
 0x2B4       1 NT AUTHORITY\SYSTEM System    False      False        Primary       Anonymous
 0x38C       1 dev22h2\user        Medium    False      False        Primary       Impersonation
 0x398       1 dev22h2\user        High      False      False        Primary       Identification
 0x3C4       1 dev22h2\user        Medium    False      False        Impersonation Impersonation
 0x3C8       1 dev22h2\user        Medium    False      False        Impersonation Impersonation
 0x3D0       1 dev22h2\user        Medium    False      False        Impersonation Impersonation
 0x3D4       1 dev22h2\user        Medium    False      False        Impersonation Impersonation

[+] Got 8 handle(s).
[*] Found 2 account(s).
    [*] NT AUTHORITY\SYSTEM
    [*] dev22h2\user
[*] Done.
```

To enumerate impersonated thread token, set `-T` flag as well as `-e` flag as follows:

```
C:\Dev>.\TokenDump.exe -e -T -d

[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to enumerate impersonated threads.

 PID  TID Session Process Name Token User          Integrity Impersonation Level
==== ==== ======= ============ =================== ========= ===================
1952 2000       0 svchost.exe  NT AUTHORITY\SYSTEM System    Impersonation
1952 2300       0 svchost.exe  NT AUTHORITY\SYSTEM System    Impersonation
3516 4348       0 svchost.exe  NT AUTHORITY\SYSTEM System    Impersonation
3516 4656       0 svchost.exe  NT AUTHORITY\SYSTEM System    Impersonation

[+] Got 4 thread(s).
[*] Found 1 account(s).
    [*] NT AUTHORITY\SYSTEM
[*] Done.
```

If you want to filter these results with token username, set filter string as `-a` option value as follows:

```
C:\Dev>.\TokenDump.exe -e -a network -d

[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to enumerate process token.

 PID Session Process Name Token User                   Integrity Restricted AppContainer
==== ======= ============ ============================ ========= ========== ============
1932       0 svchost.exe  NT AUTHORITY\NETWORK SERVICE System    False      False
3500       0 svchost.exe  NT AUTHORITY\NETWORK SERVICE System    False      False
2904       0 svchost.exe  NT AUTHORITY\NETWORK SERVICE System    False      False
2504       0 svchost.exe  NT AUTHORITY\NETWORK SERVICE System    False      False
7012       0 msdtc.exe    NT AUTHORITY\NETWORK SERVICE System    False      False
7092       0 sppsvc.exe   NT AUTHORITY\NETWORK SERVICE System    False      False
1676       0 svchost.exe  NT AUTHORITY\NETWORK SERVICE System    False      False
3584       0 WmiPrvSE.exe NT AUTHORITY\NETWORK SERVICE System    False      False
1000       0 svchost.exe  NT AUTHORITY\NETWORK SERVICE System    False      False

[+] Got 9 token information.
[*] Found 7 account(s).
    [*] NT AUTHORITY\SYSTEM
    [*] dev22h2\user
    [*] NT AUTHORITY\LOCAL SERVICE
    [*] NT AUTHORITY\NETWORK SERVICE
    [*] Font Driver Host\UMFD-0
    [*] Font Driver Host\UMFD-1
    [*] Window Manager\DWM-1
[*] Done.

C:\Dev>.\TokenDump.exe -e -a network -d -H

[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to enumerate token handles.

[Token Handle(s) - lsass.exe (PID: 768)]

Handle Session Token User                   Integrity Restricted AppContainer Token Type    Impersonation Level
====== ======= ============================ ========= ========== ============ ============= ===================
 0x914       0 NT AUTHORITY\NETWORK SERVICE System    False      False        Impersonation Impersonation

--snip--

[Token Handle(s) - msdtc.exe (PID: 7012)]

Handle Session Token User                   Integrity Restricted AppContainer Token Type Impersonation Level
====== ======= ============================ ========= ========== ============ ========== ===================
 0x23C       0 NT AUTHORITY\NETWORK SERVICE System    False      False        Primary    Anonymous

[+] Got 27 handle(s).
[*] Found 8 account(s).
    [*] NT AUTHORITY\SYSTEM
    [*] dev22h2\user
    [*] Font Driver Host\UMFD-1
    [*] Font Driver Host\UMFD-0
    [*] NT AUTHORITY\NETWORK SERVICE
    [*] Window Manager\DWM-1
    [*] NT AUTHORITY\LOCAL SERVICE
    [*] NT AUTHORITY\ANONYMOUS LOGON
[*] Done.
```

To get verbose information for a specific process, set `-s` flag and target PID as `-p` option value:

```
C:\Dev>.\TokenDump.exe -s -p 5996

[>] Trying to dump process token information.

[Token Information for StartMenuExperienceHost.exe (PID: 5996)]

ImageFilePath       : C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe
CommandLine         : "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca
Token User          : dev22h2\user (SID: S-1-5-21-3896868301-3921591151-1374190648-1001)
Token Owner         : dev22h2\user (SID: S-1-5-21-3896868301-3921591151-1374190648-1001)
Primary Group       : dev22h2\None (SID: S-1-5-21-3896868301-3921591151-1374190648-513)
Token Type          : Primary
Impersonation Level : Anonymous
Token ID            : 0x0000000000063D9A
Authentication ID   : 0x000000000001DFE5
Original ID         : 0x00000000000003E7
Modified ID         : 0x0000000000063D24
Integrity Level     : Low
Protection Level    : N/A
Session ID          : 1
Elevation Type      : Limited
Mandatory Policy    : NoWriteUp
Elevated            : False
AppContainer        : True
TokenFlags          : VirtualizeAllowed, IsFiltered, LowBox
AppContainer Name   : microsoft.windows.startmenuexperiencehost_cw5n1h2txyewy
AppContainer SID    : S-1-15-2-515815643-2845804217-1874292103-218650560-777617685-4287762684-137415000
AppContainer Number : 2
Has Linked Token    : True
Token Source        : User32
Token Source ID     : 0x000000000001DE9D


    PRIVILEGES INFORMATION
    ----------------------

    Privilege Name                State
    ============================= =========================
    SeChangeNotifyPrivilege       EnabledByDefault, Enabled
    SeIncreaseWorkingSetPrivilege Disabled


    GROUP INFORMATION
    -----------------

    Group Name                                                    Attributes
    ============================================================= =============================================
    dev22h2\None                                                  Mandatory, EnabledByDefault, Enabled
    Everyone                                                      Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\Local account and member of Administrators group UseForDenyOnly
    BUILTIN\Administrators                                        UseForDenyOnly
    BUILTIN\Users                                                 Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\INTERACTIVE                                      Mandatory, EnabledByDefault, Enabled
    CONSOLE LOGON                                                 Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\Authenticated Users                              Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\This Organization                                Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\Local account                                    Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\LogonSessionId_0_122425                          Mandatory, EnabledByDefault, Enabled, LogonId
    LOCAL                                                         Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\NTLM Authentication                              Mandatory, EnabledByDefault, Enabled
    Mandatory Label\Low Mandatory Level                           Integrity, IntegrityEnabled


    APPCONTAINER CAPABILITIES
    -------------------------

    Capability Name                                                            Flags
    ========================================================================== =======
    APPLICATION PACKAGE AUTHORITY\Your Internet connection                     Enabled
    APPLICATION PACKAGE AUTHORITY\Your home or work networks                   Enabled
    NAMED CAPABILITIES\PackageQuery                                            Enabled
    NAMED CAPABILITIES\ActivitySystem                                          Enabled
    NAMED CAPABILITIES\PreviewStore                                            Enabled
    NAMED CAPABILITIES\CortanaPermissions                                      Enabled
    NAMED CAPABILITIES\AppointmentsSystem                                      Enabled
    NAMED CAPABILITIES\TeamEditionExperience                                   Enabled
    NAMED CAPABILITIES\ShellExperience                                         Enabled
    NAMED CAPABILITIES\PackageContents                                         Enabled
    NAMED CAPABILITIES\VisualElementsSystem                                    Enabled
    NAMED CAPABILITIES\UserAccountInformation                                  Enabled
    NAMED CAPABILITIES\ActivityData                                            Enabled
    NAMED CAPABILITIES\CloudStore                                              Enabled
    NAMED CAPABILITIES\TargetedContent                                         Enabled
    NAMED CAPABILITIES\StoreAppInstall                                         Enabled
    NAMED CAPABILITIES\StoreLicenseManagement                                  Enabled
    NAMED CAPABILITIES\CortanaSettings                                         Enabled
    NAMED CAPABILITIES\DependencyTarget                                        Enabled
    NAMED CAPABILITIES\SearchSettings                                          Enabled
    NAMED CAPABILITIES\CellularData                                            Enabled
    NAMED CAPABILITIES\WifiData                                                Enabled
    PACKAGE CAPABILITY\microsoft.windows.startmenuexperiencehost_cw5n1h2txyewy Enabled
    NAMED CAPABILITIES\AccessoryManager                                        Enabled
    NAMED CAPABILITIES\UserAccountInformation                                  Enabled


    DACL INFORMATION
    ----------------

    Account Name                                            Access                      Flags Type
    ======================================================= =========================== ===== =============
    dev22h2\user                                            GenericAll                  None  AccessAllowed
    NT AUTHORITY\SYSTEM                                     GenericAll                  None  AccessAllowed
    NT AUTHORITY\LogonSessionId_0_122425                    GenericExecute, GenericRead None  AccessAllowed
    microsoft.windows.startmenuexperiencehost_cw5n1h2txyewy GenericAll                  None  AccessAllowed


    SECURITY ATTRIBUTES INFORMATION
    -------------------------------

    [*] WIN://SYSAPPID
        Flags : None
        Type  : String
            Value[0x00] : Microsoft.Windows.StartMenuExperienceHost_10.0.22621.1_neutral_neutral_cw5n1h2txyewy
            Value[0x01] : App
            Value[0x02] : Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy

    [*] WIN://PKG
        Flags : None
        Type  : UInt64
            Value[0x00] : 0x0000000200000001

    [*] WIN://PKGHOSTID
        Flags : None
        Type  : UInt64
            Value[0x00] : 0x1000000000000001

    [*] TSA://ProcUnique
        Flags : NonInheritable, Unique
        Type  : UInt64
            Value[0x00] : 0x0000000000000041
            Value[0x01] : 0x0000000000063D9B



[Linked Token Information for StartMenuExperienceHost.exe (PID: 5996)]

Token User          : dev22h2\user (SID: S-1-5-21-3896868301-3921591151-1374190648-1001)
Token Owner         : BUILTIN\Administrators (SID: S-1-5-32-544)
Primary Group       : dev22h2\None (SID: S-1-5-21-3896868301-3921591151-1374190648-513)
Token Type          : Impersonation
Impersonation Level : Identification
Token ID            : 0x000000000016ECE6
Authentication ID   : 0x000000000001DF83
Original ID         : 0x00000000000003E7
Modified ID         : 0x000000000001DFE4
Integrity Level     : High
Protection Level    : N/A
Session ID          : 1
Elevation Type      : Full
Mandatory Policy    : NoWriteUp, NewProcessMin
Elevated            : True
AppContainer        : False
TokenFlags          : NotLow
Token Source        : User32
Token Source ID     : 0x000000000001DE9D


    PRIVILEGES INFORMATION
    ----------------------

    Privilege Name                            State
    ========================================= =========================
    SeIncreaseQuotaPrivilege                  Disabled
    SeSecurityPrivilege                       Disabled
    SeTakeOwnershipPrivilege                  Disabled
    SeLoadDriverPrivilege                     Disabled
    SeSystemProfilePrivilege                  Disabled
    SeSystemtimePrivilege                     Disabled
    SeProfileSingleProcessPrivilege           Disabled
    SeIncreaseBasePriorityPrivilege           Disabled
    SeCreatePagefilePrivilege                 Disabled
    SeBackupPrivilege                         Disabled
    SeRestorePrivilege                        Disabled
    SeShutdownPrivilege                       Disabled
    SeDebugPrivilege                          Disabled
    SeSystemEnvironmentPrivilege              Disabled
    SeChangeNotifyPrivilege                   EnabledByDefault, Enabled
    SeRemoteShutdownPrivilege                 Disabled
    SeUndockPrivilege                         Disabled
    SeManageVolumePrivilege                   Disabled
    SeImpersonatePrivilege                    EnabledByDefault, Enabled
    SeCreateGlobalPrivilege                   EnabledByDefault, Enabled
    SeIncreaseWorkingSetPrivilege             Disabled
    SeTimeZonePrivilege                       Disabled
    SeCreateSymbolicLinkPrivilege             Disabled
    SeDelegateSessionUserImpersonatePrivilege Disabled


    GROUP INFORMATION
    -----------------

    Group Name                                                    Attributes
    ============================================================= =============================================
    dev22h2\None                                                  Mandatory, EnabledByDefault, Enabled
    Everyone                                                      Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\Local account and member of Administrators group Mandatory, EnabledByDefault, Enabled
    BUILTIN\Administrators                                        Mandatory, EnabledByDefault, Enabled, Owner
    BUILTIN\Users                                                 Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\INTERACTIVE                                      Mandatory, EnabledByDefault, Enabled
    CONSOLE LOGON                                                 Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\Authenticated Users                              Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\This Organization                                Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\Local account                                    Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\LogonSessionId_0_122425                          Mandatory, EnabledByDefault, Enabled, LogonId
    LOCAL                                                         Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\NTLM Authentication                              Mandatory, EnabledByDefault, Enabled
    Mandatory Label\High Mandatory Level                          Integrity, IntegrityEnabled


    DACL INFORMATION
    ----------------

    Account Name                         Access                      Flags Type
    ==================================== =========================== ===== =============
    BUILTIN\Administrators               GenericAll                  None  AccessAllowed
    NT AUTHORITY\SYSTEM                  GenericAll                  None  AccessAllowed
    NT AUTHORITY\LogonSessionId_0_122425 GenericExecute, GenericRead None  AccessAllowed


    SECURITY ATTRIBUTES INFORMATION
    -------------------------------

    [*] WIN://SYSAPPID
        Flags : None
        Type  : String
            Value[0x00] : Microsoft.Windows.StartMenuExperienceHost_10.0.22621.1_neutral_neutral_cw5n1h2txyewy
            Value[0x01] : App
            Value[0x02] : Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy

    [*] WIN://PKG
        Flags : None
        Type  : UInt64
            Value[0x00] : 0x0000000200000001

    [*] WIN://PKGHOSTID
        Flags : None
        Type  : UInt64
            Value[0x00] : 0x1000000000000001

    [*] TSA://ProcUnique
        Flags : NonInheritable, Unique
        Type  : UInt64
            Value[0x00] : 0x0000000000000041
            Value[0x01] : 0x0000000000063D9B


[*] Done.
```

If you set handle value in a specific process as `-v` option and the PID as `-p` option as well as `-s` flag, this tool get verbose information for the handle as follows:

```
C:\Dev>.\TokenDump.exe -s -p 7012 -v 0x23C -d

[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to dump token handle information.

[Token Information for Handle 0x23C of msdtc.exe (PID: 7012)]

Token User          : NT AUTHORITY\NETWORK SERVICE (SID: S-1-5-20)
Token Owner         : NT AUTHORITY\NETWORK SERVICE (SID: S-1-5-20)
Primary Group       : NT AUTHORITY\NETWORK SERVICE (SID: S-1-5-20)
Token Type          : Primary
Impersonation Level : Anonymous
Token ID            : 0x000000000007DF17
Authentication ID   : 0x00000000000003E4
Original ID         : 0x00000000000003E7
Modified ID         : 0x000000000007DEE2
Integrity Level     : System
Protection Level    : N/A
Session ID          : 0
Elevation Type      : Default
Mandatory Policy    : NoWriteUp, NewProcessMin
Elevated            : False
AppContainer        : False
TokenFlags          : IsFiltered, NotLow
Has Linked Token    : False
Token Source        : N/A
Token Source ID     : N/A


    PRIVILEGES INFORMATION
    ----------------------

    Privilege Name          State
    ======================= =========================
    SeChangeNotifyPrivilege EnabledByDefault, Enabled
    SeCreateGlobalPrivilege EnabledByDefault, Enabled


    GROUP INFORMATION
    -----------------

    Group Name                             Attributes
    ====================================== ====================================================
    Mandatory Label\System Mandatory Level Integrity, IntegrityEnabled
    Everyone                               Mandatory, EnabledByDefault, Enabled
    BUILTIN\Users                          Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\SERVICE                   Mandatory, EnabledByDefault, Enabled
    CONSOLE LOGON                          Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\Authenticated Users       Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\This Organization         Mandatory, EnabledByDefault, Enabled
    NT SERVICE\MSDTC                       EnabledByDefault, Enabled, Owner
    NT AUTHORITY\LogonSessionId_0_515780   Mandatory, EnabledByDefault, Enabled, Owner, LogonId
    LOCAL                                  Mandatory, EnabledByDefault, Enabled


    DACL INFORMATION
    ----------------

    Account Name        Access      Flags Type
    =================== =========== ===== =============
    NT AUTHORITY\SYSTEM GenericAll  None  AccessAllowed
    OWNER RIGHTS        ReadControl None  AccessAllowed
    NT SERVICE\MSDTC    GenericAll  None  AccessAllowed


    SECURITY ATTRIBUTES INFORMATION
    -------------------------------

    [*] TSA://ProcUnique
        Flags : NonInheritable, Unique
        Type  : UInt64
            Value[0x00] : 0x0000000000000070
            Value[0x01] : 0x000000000007DF18


[*] Done.
```

To investigate impersonate token applied to thread, set the thread ID as `-t` option as follows:

```
C:\Dev>.\TokenDump.exe -e -T -d

[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to enumerate impersonated threads.

 PID  TID Session Process Name Token User          Integrity Impersonation Level
==== ==== ======= ============ =================== ========= ===================
1952 2000       0 svchost.exe  NT AUTHORITY\SYSTEM System    Impersonation
1952 2300       0 svchost.exe  NT AUTHORITY\SYSTEM System    Impersonation
3516 4348       0 svchost.exe  NT AUTHORITY\SYSTEM System    Impersonation
3516 4656       0 svchost.exe  NT AUTHORITY\SYSTEM System    Impersonation

[+] Got 4 thread(s).
[*] Found 1 account(s).
    [*] NT AUTHORITY\SYSTEM
[*] Done.


C:\Dev>.\TokenDump.exe -s -p 3516 -t 4656 -d

[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[>] Trying to dump thread token information.

[Token Information for svchost.exe (PID: 3516, TID: 4656)]

Token User          : NT AUTHORITY\SYSTEM (SID: S-1-5-18)
Token Owner         : NT AUTHORITY\SYSTEM (SID: S-1-5-18)
Primary Group       : NT AUTHORITY\SYSTEM (SID: S-1-5-18)
Token Type          : Impersonation
Impersonation Level : Impersonation
Token ID            : 0x0000000000038CC4
Authentication ID   : 0x00000000000003E7
Original ID         : 0x00000000000003E7
Modified ID         : 0x000000000002CE61
Integrity Level     : System
Protection Level    : N/A
Session ID          : 0
Elevation Type      : Default
Mandatory Policy    : NoWriteUp, NewProcessMin
Elevated            : True
AppContainer        : False
TokenFlags          : IsFiltered, NotLow, EnforceRedirectionTrust
Has Linked Token    : False
Token Source        : N/A
Token Source ID     : N/A


    PRIVILEGES INFORMATION
    ----------------------

    Privilege Name                State
    ============================= =========================
    SeAssignPrimaryTokenPrivilege Disabled
    SeTcbPrivilege                EnabledByDefault, Enabled
    SeSecurityPrivilege           Disabled
    SeSystemProfilePrivilege      EnabledByDefault, Enabled
    SeDebugPrivilege              EnabledByDefault, Enabled
    SeChangeNotifyPrivilege       EnabledByDefault, Enabled
    SeImpersonatePrivilege        EnabledByDefault, Enabled
    SeCreateGlobalPrivilege       EnabledByDefault, Enabled


    GROUP INFORMATION
    -----------------

    Group Name                             Attributes
    ====================================== ====================================================
    Mandatory Label\System Mandatory Level Integrity, IntegrityEnabled
    Everyone                               Mandatory, EnabledByDefault, Enabled
    BUILTIN\Users                          Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\SERVICE                   Mandatory, EnabledByDefault, Enabled
    CONSOLE LOGON                          Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\Authenticated Users       Mandatory, EnabledByDefault, Enabled
    NT AUTHORITY\This Organization         Mandatory, EnabledByDefault, Enabled
    NT SERVICE\DiagTrack                   EnabledByDefault, Enabled, Owner
    NT AUTHORITY\LogonSessionId_0_180260   Mandatory, EnabledByDefault, Enabled, Owner, LogonId
    LOCAL                                  Mandatory, EnabledByDefault, Enabled
    BUILTIN\Administrators                 EnabledByDefault, Enabled, Owner


    DACL INFORMATION
    ----------------

    Account Name         Access      Flags Type
    ==================== =========== ===== =============
    NT AUTHORITY\SYSTEM  GenericAll  None  AccessAllowed
    OWNER RIGHTS         ReadControl None  AccessAllowed
    NT SERVICE\DiagTrack GenericAll  None  AccessAllowed


    SECURITY ATTRIBUTES INFORMATION
    -------------------------------

    [*] TSA://ProcUnique
        Flags : NonInheritable, Unique
        Type  : UInt64
            Value[0x00] : 0x0000000000000047
            Value[0x01] : 0x000000000002C0FA


[*] Done.
```



## TrustExec

[Back to Top](#privfu)

[Project](./TrustExec)

This tool is to execute process as `NT SERVICE\TrustedInstaller` group account.
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
        -e, --extra     : Specifies extra group SID(s) to add.

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

If you want to add extra group account to token for new process, use `-e` option as follows:

```
C:\dev>TrustExec.exe -m exec -s -e S-1-5-20

[>] Parsing group SID(s).
[+] "NT AUTHORITY\NETWORK SERVICE" is added as an extra group.
    |-> SID  : S-1-5-20
    |-> Type : SidTypeWellKnownGroup
[>] Trying to get SYSTEM.
[>] Trying to impersonate as smss.exe.
[+] SeCreateTokenPrivilege is enabled successfully.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[>] Trying to impersonate thread token.
    |-> Current Thread ID : 4392
[+] Impersonation is successful.
[>] Trying to create an elevated primary token.
[+] An elevated primary token is created successfully.
[>] Trying to create a token assigned process.

Microsoft Windows [Version 10.0.22000.318]
(c) Microsoft Corporation. All rights reserved.

C:\dev>whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID                                                            Attributes
====================================== ================ ============================================================== ==================================================
BUILTIN\Administrators                 Alias            S-1-5-32-544                                                   Enabled by default, Enabled group, Group owner
Everyone                               Well-known group S-1-1-0                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                                       Mandatory group, Enabled by default, Enabled group
Mandatory Label\System Mandatory Level Label            S-1-16-16384

NT SERVICE\TrustedInstaller            Well-known group S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464 Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK SERVICE           Well-known group S-1-5-20                                                       Mandatory group, Enabled by default, Enabled group
```

To add multiple groups, specifies SIDs as comma separated value:

```
C:\dev>TrustExec.exe -m exec -s -e S-1-5-20,S-1-5-32-551

[>] Parsing group SID(s).
[+] "NT AUTHORITY\NETWORK SERVICE" is added as an extra group.
    |-> SID  : S-1-5-20
    |-> Type : SidTypeWellKnownGroup
[+] "BUILTIN\Backup Operators" is added as an extra group.
    |-> SID  : S-1-5-32-551
    |-> Type : SidTypeAlias
[>] Trying to get SYSTEM.
[>] Trying to impersonate as smss.exe.
[+] SeCreateTokenPrivilege is enabled successfully.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[>] Trying to impersonate thread token.
    |-> Current Thread ID : 3104
[+] Impersonation is successful.
[>] Trying to create an elevated primary token.
[+] An elevated primary token is created successfully.
[>] Trying to create a token assigned process.

Microsoft Windows [Version 10.0.22000.318]
(c) Microsoft Corporation. All rights reserved.

C:\dev>whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID                                                            Attributes
====================================== ================ ============================================================== ==================================================
BUILTIN\Administrators                 Alias            S-1-5-32-544                                                   Enabled by default, Enabled group, Group owner
Everyone                               Well-known group S-1-1-0                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                                       Mandatory group, Enabled by default, Enabled group
Mandatory Label\System Mandatory Level Label            S-1-16-16384

NT SERVICE\TrustedInstaller            Well-known group S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464 Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK SERVICE           Well-known group S-1-5-20                                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators               Alias            S-1-5-32-551                                                   Mandatory group, Enabled by default, Enabled group
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
