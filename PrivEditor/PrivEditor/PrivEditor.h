#pragma once

// BIT Mask for _SEP_TOKEN_PRIVILEGES
#define MASK_CREATE_TOKEN                      0x0000000000000004ULL // SeCreateTokenPrivilege
#define MASK_ASSIGN_PRIMARY_TOKEN              0x0000000000000008ULL // SeAssignPrimaryTokenPrivilege
#define MASK_LOCK_MEMORY                       0x0000000000000010ULL // SeLockMemoryPrivilege
#define MASK_INCREASE_QUOTA                    0x0000000000000020ULL // SeIncreaseQuotaPrivilege
#define MASK_MACHINE_ACCOUNT                   0x0000000000000040ULL // SeMachineAccountPrivilege
#define MASK_TCB                               0x0000000000000080ULL // SeTcbPrivilege
#define MASK_SECURITY                          0x0000000000000100ULL // SeSecurityPrivilege
#define MASK_TAKE_OWNERSHIP                    0x0000000000000200ULL // SeTakeOwnershipPrivilege
#define MASK_LOAD_DRIVER                       0x0000000000000400ULL // SeLoadDriverPrivilege
#define MASK_SYSTEM_PROFILE                    0x0000000000000800ULL // SeSystemProfilePrivilege
#define MASK_SYSTEMTIME                        0x0000000000001000ULL // SeSystemtimePrivilege
#define MASK_PROFILE_SINGLE_PROCESS            0x0000000000002000ULL // SeProfileSingleProcessPrivilege
#define MASK_INCREASE_BASE_PRIORITY            0x0000000000004000ULL // SeIncreaseBasePriorityPrivilege
#define MASK_CREATE_PAGEFILE                   0x0000000000008000ULL // SeCreatePagefilePrivilege
#define MASK_CREATE_PERMANENT                  0x0000000000010000ULL // SeCreatePermanentPrivilege
#define MASK_BACKUP                            0x0000000000020000ULL // SeBackupPrivilege
#define MASK_RESTORE                           0x0000000000040000ULL // SeRestorePrivilege
#define MASK_SHUTDOWN                          0x0000000000080000ULL // SeShutdownPrivilege
#define MASK_DEBUG                             0x0000000000100000ULL // SeDebugPrivilege
#define MASK_AUDIT                             0x0000000000200000ULL // SeAuditPrivilege
#define MASK_SYSTEM_ENVIRONMENT                0x0000000000400000ULL // SeSystemEnvironmentPrivilege
#define MASK_CHANGE_NOTIFY                     0x0000000000800000ULL // SeChangeNotifyPrivilege
#define MASK_REMOTE_SHUTDOWN                   0x0000000001000000ULL // SeRemoteShutdownPrivilege
#define MASK_UNDOCK                            0x0000000002000000ULL // SeUndockPrivilege
#define MASK_SYNC_AGENT                        0x0000000004000000ULL // SeSyncAgentPrivilege
#define MASK_ENABLE_DELEGATION                 0x0000000008000000ULL // SeEnableDelegationPrivilege
#define MASK_MANAGE_VOLUME                     0x0000000010000000ULL // SeManageVolumePrivilege
#define MASK_IMPERSONATE                       0x0000000020000000ULL // SeImpersonatePrivilege
#define MASK_CREATE_GLOBAL                     0x0000000040000000ULL // SeCreateGlobalPrivilege
#define MASK_TRUSTED_CRED_MAN_ACCESS           0x0000000080000000ULL // SeTrustedCredManAccessPrivilege
#define MASK_RELABEL                           0x0000000100000000ULL // SeRelabelPrivilege
#define MASK_INCREASE_WORKING_SET              0x0000000200000000ULL // SeIncreaseWorkingSetPrivilege
#define MASK_TIME_ZONE                         0x0000000400000000ULL // SeTimeZonePrivilege
#define MASK_CREATE_SYMBOLIC_LINK              0x0000000800000000ULL // SeCreateSymbolicLinkPrivilege
#define MASK_DELEGATE_SESSION_USER_IMPERSONATE 0x0000001000000000ULL // SeDelegateSessionUserImpersonatePrivilege
#define MASK_ALL                               0x0000001ffffffffcULL // Mask for all privileges

typedef struct _KERNEL_OFFSETS
{
    // nt!_EPROCESS
    ULONG UniqueProcessId;
    ULONG ActiveProcessLinks;
    ULONG ImageFilePointer;
    ULONG ImageFileName;
    ULONG Token;
    // nt!_Token
    ULONG Privileges;
    // nt!_SEP_TOKEN_PRIVILEGES
    ULONG Present;
    ULONG Enabled;
    ULONG EnabledByDefault;
} KERNEL_OFFSETS, * PKERNEL_OFFSETS;

typedef struct _PROCESS_CONTEXT
{
    ULONG64 Eprocess;
    ULONG64 Token;
    ULONG64 Privileges;
    CHAR ProcessName[256];
} PROCESS_CONTEXT, * PPROCESS_CONTEXT;

extern BOOL g_IsInitialized;
extern ULONG64 g_SystemProcess;
extern KERNEL_OFFSETS g_KernelOffsets;
