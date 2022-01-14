#include "pch.h"
#include "utils.h"
#include "helpers.h"
#include "PrivEditor.h"

ULONG_PTR g_Eprocess = 0;
KERNEL_OFFSETS g_Offsets = { 0 };

BOOL DisableAllAvailable(ULONG_PTR pTokenPrivilege)
{
    return WriteQword(pTokenPrivilege + g_Offsets.Enabled, 0ULL);
}


BOOL EnableAllAvailable(ULONG_PTR pTokenPrivilege)
{
    ULONG64 available;
    ReadQword(pTokenPrivilege + g_Offsets.Present, &available);

    return WriteQword(pTokenPrivilege + g_Offsets.Enabled, available);
}


VOID FlipPresentBit(ULONG_PTR pTokenPrivilege, ULONG64 mask)
{
    ULONG64 currentPrivileges;
    ULONG64 flippedPrivileges;

    ReadQword(pTokenPrivilege + g_Offsets.Present, &currentPrivileges);
    flippedPrivileges = currentPrivileges ^ mask;
    WriteQword(pTokenPrivilege + g_Offsets.Present, flippedPrivileges);
}


VOID FlipEnabledBit(ULONG_PTR pTokenPrivilege, ULONG64 mask)
{
    ULONG64 currentPrivileges;
    ULONG64 flippedPrivileges;

    ReadQword(pTokenPrivilege + g_Offsets.Enabled, &currentPrivileges);
    flippedPrivileges = currentPrivileges ^ mask;
    WriteQword(pTokenPrivilege + g_Offsets.Enabled, flippedPrivileges);
}


ULONG64 GetPrivilegeMask(std::string priv)
{
    if (_stricmp(priv.c_str(), "All") == 0)
        return MASK_ALL;
    else if (_stricmp(priv.c_str(), "CreateToken") == 0)
        return MASK_CREATE_TOKEN;
    else if (_stricmp(priv.c_str(), "AssignPrimaryToken") == 0)
        return MASK_ASSIGN_PRIMARY_TOKEN;
    else if (_stricmp(priv.c_str(), "LockMemory") == 0)
        return MASK_LOCK_MEMORY;
    else if (_stricmp(priv.c_str(), "IncreaseQuota") == 0)
        return MASK_INCREASE_QUOTA;
    else if (_stricmp(priv.c_str(), "MachineAccount") == 0)
        return MASK_MACHINE_ACCOUNT;
    else if (_stricmp(priv.c_str(), "Tcb") == 0)
        return MASK_TCB;
    else if (_stricmp(priv.c_str(), "Security") == 0)
        return MASK_SECURITY;
    else if (_stricmp(priv.c_str(), "TakeOwnership") == 0)
        return MASK_TAKE_OWNERSHIP;
    else if (_stricmp(priv.c_str(), "LoadDriver") == 0)
        return MASK_LOAD_DRIVER;
    else if (_stricmp(priv.c_str(), "SystemProfile") == 0)
        return MASK_SYSTEM_PROFILE;
    else if (_stricmp(priv.c_str(), "Systemtime") == 0)
        return MASK_SYSTEMTIME;
    else if (_stricmp(priv.c_str(), "ProfileSingleProcess") == 0)
        return MASK_PROFILE_SINGLE_PROCESS;
    else if (_stricmp(priv.c_str(), "IncreaseBasePriority") == 0)
        return MASK_INCREASE_BASE_PRIORITY;
    else if (_stricmp(priv.c_str(), "CreatePagefile") == 0)
        return MASK_CREATE_PAGEFILE;
    else if (_stricmp(priv.c_str(), "CreatePermanent") == 0)
        return MASK_CREATE_PERMANENT;
    else if (_stricmp(priv.c_str(), "Backup") == 0)
        return MASK_BACKUP;
    else if (_stricmp(priv.c_str(), "Restore") == 0)
        return MASK_RESTORE;
    else if (_stricmp(priv.c_str(), "Shutdown") == 0)
        return MASK_SHUTDOWN;
    else if (_stricmp(priv.c_str(), "Debug") == 0)
        return MASK_DEBUG;
    else if (_stricmp(priv.c_str(), "Audit") == 0)
        return MASK_AUDIT;
    else if (_stricmp(priv.c_str(), "SystemEnvironment") == 0)
        return MASK_SYSTEM_ENVIRONMENT;
    else if (_stricmp(priv.c_str(), "ChangeNotify") == 0)
        return MASK_CHANGE_NOTIFY;
    else if (_stricmp(priv.c_str(), "RemoteShutdown") == 0)
        return MASK_REMOTE_SHUTDOWN;
    else if (_stricmp(priv.c_str(), "Undock") == 0)
        return MASK_UNDOCK;
    else if (_stricmp(priv.c_str(), "SyncAgent") == 0)
        return MASK_SYNC_AGENT;
    else if (_stricmp(priv.c_str(), "EnableDelegation") == 0)
        return MASK_ENABLE_DELEGATION;
    else if (_stricmp(priv.c_str(), "ManageVolume") == 0)
        return MASK_MANAGE_VOLUME;
    else if (_stricmp(priv.c_str(), "Impersonate") == 0)
        return MASK_IMPERSONATE;
    else if (_stricmp(priv.c_str(), "CreateGlobal") == 0)
        return MASK_CREATE_GLOBAL;
    else if (_stricmp(priv.c_str(), "TrustedCredManAccess") == 0)
        return MASK_TRUSTED_CRED_MAN_ACCESS;
    else if (_stricmp(priv.c_str(), "Relabel") == 0)
        return MASK_RELABEL;
    else if (_stricmp(priv.c_str(), "IncreaseWorkingSet") == 0)
        return MASK_INCREASE_WORKING_SET;
    else if (_stricmp(priv.c_str(), "TimeZone") == 0)
        return MASK_TIME_ZONE;
    else if (_stricmp(priv.c_str(), "CreateSymbolicLink") == 0)
        return MASK_CREATE_SYMBOLIC_LINK;
    else if (_stricmp(priv.c_str(), "DelegateSessionUserImpersonate") == 0)
        return MASK_DELEGATE_SESSION_USER_IMPERSONATE;
    else
        return 0xdeadbeefdeadbeefULL;
}


std::string GetPrivilegeName(ULONG64 mask)
{
    if (mask == MASK_CREATE_TOKEN)
        return std::string("SeCreateTokenPrivilege");
    else if (mask == MASK_ASSIGN_PRIMARY_TOKEN)
        return std::string("SeAssignPrimaryTokenPrivilege");
    else if (mask == MASK_LOCK_MEMORY)
        return std::string("SeLockMemoryPrivilege");
    else if (mask == MASK_INCREASE_QUOTA)
        return std::string("SeIncreaseQuotaPrivilege");
    else if (mask == MASK_MACHINE_ACCOUNT)
        return std::string("SeMachineAccountPrivilege");
    else if (mask == MASK_TCB)
        return std::string("SeTcbPrivilege");
    else if (mask == MASK_SECURITY)
        return std::string("SeSecurityPrivilege");
    else if (mask == MASK_TAKE_OWNERSHIP)
        return std::string("SeTakeOwnershipPrivilege");
    else if (mask == MASK_LOAD_DRIVER)
        return std::string("SeLoadDriverPrivilege");
    else if (mask == MASK_SYSTEM_PROFILE)
        return std::string("SeSystemProfilePrivilege");
    else if (mask == MASK_SYSTEMTIME)
        return std::string("SeSystemtimePrivilege");
    else if (mask == MASK_PROFILE_SINGLE_PROCESS)
        return std::string("SeProfileSingleProcessPrivilege");
    else if (mask == MASK_INCREASE_BASE_PRIORITY)
        return std::string("SeIncreaseBasePriorityPrivilege");
    else if (mask == MASK_CREATE_PAGEFILE)
        return std::string("SeCreatePagefilePrivilege");
    else if (mask == MASK_CREATE_PERMANENT)
        return std::string("SeCreatePermanentPrivilege");
    else if (mask == MASK_BACKUP)
        return std::string("SeBackupPrivilege");
    else if (mask == MASK_RESTORE)
        return std::string("SeRestorePrivilege");
    else if (mask == MASK_SHUTDOWN)
        return std::string("SeShutdownPrivilege");
    else if (mask == MASK_DEBUG)
        return std::string("SeDebugPrivilege");
    else if (mask == MASK_AUDIT)
        return std::string("SeAuditPrivilege");
    else if (mask == MASK_SYSTEM_ENVIRONMENT)
        return std::string("SeSystemEnvironmentPrivilege");
    else if (mask == MASK_CHANGE_NOTIFY)
        return std::string("SeChangeNotifyPrivilege");
    else if (mask == MASK_REMOTE_SHUTDOWN)
        return std::string("SeRemoteShutdownPrivilege");
    else if (mask == MASK_UNDOCK)
        return std::string("SeUndockPrivilege");
    else if (mask == MASK_SYNC_AGENT)
        return std::string("SeSyncAgentPrivilege");
    else if (mask == MASK_ENABLE_DELEGATION)
        return std::string("SeEnableDelegationPrivilege");
    else if (mask == MASK_MANAGE_VOLUME)
        return std::string("SeManageVolumePrivilege");
    else if (mask == MASK_IMPERSONATE)
        return std::string("SeImpersonatePrivilege");
    else if (mask == MASK_CREATE_GLOBAL)
        return std::string("SeCreateGlobalPrivilege");
    else if (mask == MASK_TRUSTED_CRED_MAN_ACCESS)
        return std::string("SeTrustedCredManAccessPrivilege");
    else if (mask == MASK_RELABEL)
        return std::string("SeRelabelPrivilege");
    else if (mask == MASK_INCREASE_WORKING_SET)
        return std::string("SeIncreaseWorkingSetPrivilege");
    else if (mask == MASK_TIME_ZONE)
        return std::string("SeTimeZonePrivilege");
    else if (mask == MASK_CREATE_SYMBOLIC_LINK)
        return std::string("SeCreateSymbolicLinkPrivilege");
    else if (mask == MASK_DELEGATE_SESSION_USER_IMPERSONATE)
        return std::string("SeDelegateSessionUserImpersonatePrivilege");
    else
        return std::string("");
}


std::string GetFileName(ULONG_PTR pEprocess)
{
    ULONG_PTR pImageFilePointer;
    ULONG_PTR pUnicodeBuffer;
    std::wstring unicodeName;
    size_t ret;
    size_t size;
    char* buffer;
    ReadPointer(pEprocess + g_Offsets.ImageFilePointer, &pImageFilePointer);
    ReadPointer(pImageFilePointer + g_Offsets.FileName + g_Offsets.Buffer, &pUnicodeBuffer);

    if (IsKernelAddress(pUnicodeBuffer)) {
        unicodeName = ReadUnicodeString(pUnicodeBuffer, 128);
        size = unicodeName.length() * MB_CUR_MAX + 1;
        buffer = new char[size];
        wcstombs_s(&ret, buffer, size, unicodeName.c_str(), size);

        return std::string(buffer);
    }
    else
        return std::string("");
}


std::string GetImageFileName(ULONG_PTR pEprocess)
{
    return ReadAnsiString(pEprocess + g_Offsets.ImageFileName, 16);
}


std::string GetProcessName(ULONG_PTR pEprocess)
{
    std::regex re_expected(R"([\S ]+\\([^\\]+))");
    std::smatch matches;
    std::string fileName = GetFileName(pEprocess);
    std::string imageFileName = GetImageFileName(pEprocess);

    if (fileName.empty())
        return imageFileName;

    if (std::regex_match(fileName, matches, re_expected))
        return matches[1].str();

    return std::string("");
}


ULONG_PTR GetTokenPointer(ULONG_PTR pEprocess)
{
    ULONG_PTR pTokenPrivilege;
    ReadPointer(pEprocess + g_Offsets.Token, &pTokenPrivilege);

    if (IsPtr64())
        pTokenPrivilege &= 0xfffffffffffffff0ULL;
    else
        pTokenPrivilege &= 0xfffffff8UL;

    pTokenPrivilege += g_Offsets.Privileges;

    return pTokenPrivilege;
}


BOOL Initialize()
{
    ULONG_PTR pKthread = GetExpression("nt!KiInitialThread");

    if (pKthread == NULL) {
        dprintf("[!] Failed to resolve Kernel address.\n");
        return FALSE;
    }

    if (FAILED(GetFieldOffset("nt!_KTHREAD", "ApcState", &g_Offsets.ApcState)))
        return FALSE;

    if (FAILED(GetFieldOffset("nt!_KAPC_STATE", "Process", &g_Offsets.Process)))
        return FALSE;

    if (FAILED(GetFieldOffset("nt!_EPROCESS", "UniqueProcessId", &g_Offsets.UniqueProcessId)))
        return FALSE;

    if (FAILED(GetFieldOffset("nt!_EPROCESS", "ActiveProcessLinks", &g_Offsets.ActiveProcessLinks)))
        return FALSE;

    if (FAILED(GetFieldOffset("nt!_EPROCESS", "Token", &g_Offsets.Token)))
        return FALSE;

    if (FAILED(GetFieldOffset("nt!_EPROCESS", "ImageFilePointer", &g_Offsets.ImageFilePointer)))
        return FALSE;

    if (FAILED(GetFieldOffset("nt!_EPROCESS", "ImageFileName", &g_Offsets.ImageFileName)))
        return FALSE;

    if (FAILED(GetFieldOffset("nt!_TOKEN", "Privileges", &g_Offsets.Privileges)))
        return FALSE;

    if (FAILED(GetFieldOffset("nt!_SEP_TOKEN_PRIVILEGES", "Present", &g_Offsets.Present)))
        return FALSE;

    if (FAILED(GetFieldOffset("nt!_SEP_TOKEN_PRIVILEGES", "Enabled", &g_Offsets.Enabled)))
        return FALSE;

    if (FAILED(GetFieldOffset("nt!_SEP_TOKEN_PRIVILEGES", "EnabledByDefault", &g_Offsets.EnabledByDefault)))
        return FALSE;

    if (FAILED(GetFieldOffset("ntdll!_FILE_OBJECT", "FileName", &g_Offsets.FileName)))
        return FALSE;

    if (FAILED(GetFieldOffset("ntdll!_UNICODE_STRING", "Buffer", &g_Offsets.Buffer)))
        return FALSE;

    ULONG_PTR pApcState;

    // Resolve System EPROCESS
    if (!ReadPointer(pKthread + g_Offsets.ApcState, &pApcState))
        return FALSE;

    if (!ReadPointer(pApcState + g_Offsets.Process, &g_Eprocess))
        return FALSE;

    return TRUE;
}


BOOL IsEnabled(ULONG_PTR pTokenPrivilege, ULONG64 mask)
{
    ULONG64 current;
    ReadQword(pTokenPrivilege + g_Offsets.Enabled, &current);

    if (mask == MASK_ALL)
        return (current == MASK_ALL);
    else
        return ((current & mask) != 0);
}


BOOL IsInitialized()
{
    return IsKernelAddress(g_Eprocess);
}


BOOL IsPresent(ULONG_PTR pTokenPrivilege, ULONG64 mask)
{
    ULONG64 current;
    ReadQword(pTokenPrivilege + g_Offsets.Present, &current);

    if (mask == MASK_ALL)
        return (current == MASK_ALL);
    else
        return ((current & mask) != 0);
}


std::map<ULONG_PTR, ULONG_PTR> ListEprocess()
{
    ULONG_PTR uniqueProcessId;
    ULONG_PTR token;
    ULONG_PTR currentProcess = g_Eprocess;
    ULONG_PTR activeProcessLink;
    std::map<ULONG_PTR, ULONG_PTR> processList;

    for (int count = 0; count < 1024; count++) {
        ReadPointer(currentProcess + g_Offsets.UniqueProcessId, &uniqueProcessId);
        ReadPointer(currentProcess + g_Offsets.Token, &token);

        if (IsPtr64())
            token &= 0xfffffffffffffff0ULL;
        else
            token &= 0xfffffff8UL;

        if (token == 0)
            uniqueProcessId = 0;

        if (processList.find(uniqueProcessId) == processList.end())
            processList[uniqueProcessId] = currentProcess;
        else
            break;

        ReadPointer(currentProcess + g_Offsets.ActiveProcessLinks, &activeProcessLink);
        currentProcess = activeProcessLink - g_Offsets.ActiveProcessLinks;
    }

    return processList;
}


VOID PrintDebugInfo()
{
    dprintf("[DEBUG INFORMATION]\n");
    dprintf("nt!_EPROCESS for System @ 0x%p\n", g_Eprocess);
    dprintf("nt!_KTHREAD\n");
    dprintf("    +0x%-4x : %s\n", g_Offsets.ApcState, "ApcState");
    dprintf("nt!_KAPC_STATE\n");
    dprintf("    +0x%-4x : %s\n", g_Offsets.Process, "Process");
    dprintf("nt!_EPROCESS\n");
    dprintf("    +0x%-4x : %s\n", g_Offsets.UniqueProcessId, "UniqueProcessId");
    dprintf("    +0x%-4x : %s\n", g_Offsets.ActiveProcessLinks, "ActiveProcessLinks");
    dprintf("    +0x%-4x : %s\n", g_Offsets.Token, "Token");
    dprintf("    +0x%-4x : %s\n", g_Offsets.ImageFilePointer, "ImageFilePointer");
    dprintf("    +0x%-4x : %s\n", g_Offsets.ImageFileName, "ImageFileName");
    dprintf("nt!_TOKEN\n");
    dprintf("    +0x%-4x : %s\n", g_Offsets.Privileges, "Privileges");
    dprintf("nt!_SEP_TOKEN_PRIVILEGES\n");
    dprintf("    +0x%-4x : %s\n", g_Offsets.Present, "Present");
    dprintf("    +0x%-4x : %s\n", g_Offsets.Enabled, "Enabled");
    dprintf("    +0x%-4x : %s\n", g_Offsets.EnabledByDefault, "EnabledByDefault");
    dprintf("ntdll!_FILE_OBJECT\n");
    dprintf("    +0x%-4x : %s\n", g_Offsets.FileName, "FileName");
    dprintf("ntdll!_UNICODE_STRING\n");
    dprintf("    +0x%-4x : %s\n", g_Offsets.Buffer, "Buffer");
    dprintf("\n");
    dprintf("\n_EPROCESS for System (PID : 4) @ 0x%p\n\n", g_Eprocess);
}


VOID PrintPrivileges()
{
    dprintf("    Privilege : Specifies privilege to enable (case insensitive). Available privileges are following.\n\n");
    dprintf("        + CreateToken                    : SeCreateTokenPrivilege.\n");
    dprintf("        + AssignPrimaryToken             : SeAssignPrimaryTokenPrivilege.\n");
    dprintf("        + LockMemory                     : SeLockMemoryPrivilege.\n");
    dprintf("        + IncreaseQuota                  : SeIncreaseQuotaPrivilege.\n");
    dprintf("        + MachineAccount                 : SeMachineAccountPrivilege.\n");
    dprintf("        + Tcb                            : SeTcbPrivilege.\n");
    dprintf("        + Security                       : SeSecurityPrivilege.\n");
    dprintf("        + TakeOwnership                  : SeTakeOwnershipPrivilege.\n");
    dprintf("        + LoadDriver                     : SeLoadDriverPrivilege.\n");
    dprintf("        + SystemProfile                  : SeSystemProfilePrivilege.\n");
    dprintf("        + Systemtime                     : SeSystemtimePrivilege.\n");
    dprintf("        + ProfileSingleProcess           : SeProfileSingleProcessPrivilege.\n");
    dprintf("        + IncreaseBasePriority           : SeIncreaseBasePriorityPrivilege.\n");
    dprintf("        + CreatePagefile                 : SeCreatePagefilePrivilege.\n");
    dprintf("        + CreatePermanent                : SeCreatePermanentPrivilege.\n");
    dprintf("        + Backup                         : SeBackupPrivilege.\n");
    dprintf("        + Restore                        : SeRestorePrivilege.\n");
    dprintf("        + Shutdown                       : SeShutdownPrivilege.\n");
    dprintf("        + Debug                          : SeDebugPrivilege.\n");
    dprintf("        + Audit                          : SeAuditPrivilege.\n");
    dprintf("        + SystemEnvironment              : SeSystemEnvironmentPrivilege.\n");
    dprintf("        + ChangeNotify                   : SeChangeNotifyPrivilege.\n");
    dprintf("        + RemoteShutdown                 : SeRemoteShutdownPrivilege.\n");
    dprintf("        + Undock                         : SeUndockPrivilege.\n");
    dprintf("        + SyncAgent                      : SeSyncAgentPrivilege.\n");
    dprintf("        + EnableDelegation               : SeEnableDelegationPrivilege.\n");
    dprintf("        + ManageVolume                   : SeManageVolumePrivilege.\n");
    dprintf("        + Impersonate                    : SeImpersonatePrivilege.\n");
    dprintf("        + CreateGlobal                   : SeCreateGlobalPrivilege.\n");
    dprintf("        + TrustedCredManAccess           : SeTrustedCredManAccessPrivilege.\n");
    dprintf("        + Relabel                        : SeRelabelPrivilege.\n");
    dprintf("        + IncreaseWorkingSet             : SeIncreaseWorkingSetPrivilege.\n");
    dprintf("        + TimeZone                       : SeTimeZonePrivilege.\n");
    dprintf("        + CreateSymbolicLink             : SeCreateSymbolicLinkPrivilege.\n");
    dprintf("        + DelegateSessionUserImpersonate : SeDelegateSessionUserImpersonatePrivilege.\n");
    dprintf("        + All                            : All privileges.\n\n");
}


BOOL RemoveEnabled(ULONG_PTR pTokenPrivilege, ULONG64 mask)
{
    ULONG64 current;
    ULONG64 privMask = MASK_ALL ^ mask;
    ReadQword(pTokenPrivilege + g_Offsets.Enabled, &current);

    return WriteQword(pTokenPrivilege + g_Offsets.Enabled, current & privMask);
}


BOOL RemovePresent(ULONG_PTR pTokenPrivilege, ULONG64 mask)
{
    ULONG64 current;
    ULONG64 privMask = MASK_ALL ^ mask;
    ReadQword(pTokenPrivilege + g_Offsets.Present, &current);

    return WriteQword(pTokenPrivilege + g_Offsets.Present, current & privMask);
}


BOOL SetEnabled(ULONG_PTR pTokenPrivilege, ULONG64 mask)
{
    ULONG64 current;
    ReadQword(pTokenPrivilege + g_Offsets.Enabled, &current);

    return WriteQword(pTokenPrivilege + g_Offsets.Enabled, current | mask);
}


BOOL SetPresent(ULONG_PTR pTokenPrivilege, ULONG64 mask)
{
    ULONG64 current;
    ReadQword(pTokenPrivilege + g_Offsets.Present, &current);

    return WriteQword(pTokenPrivilege + g_Offsets.Present, current | mask);
}
