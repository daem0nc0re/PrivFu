#include "pch.h"
#include "PrivEditor.h"
#include "helpers.h"
#include "utils.h"

BOOL DisableAllAvailable(ULONG64 pTokenPrivilege)
{
    return WriteQword(pTokenPrivilege + g_KernelOffsets.Enabled, 0ULL);
}


BOOL EnableAllAvailable(ULONG64 pTokenPrivilege)
{
    ULONG64 available;
    ReadQword(pTokenPrivilege + g_KernelOffsets.Present, &available);

    return WriteQword(pTokenPrivilege + g_KernelOffsets.Enabled, available);
}


VOID FlipPresentBit(ULONG64 pTokenPrivilege, ULONG64 mask)
{
    ULONG64 currentPrivileges;
    ULONG64 flippedPrivileges;

    ReadQword(pTokenPrivilege + g_KernelOffsets.Present, &currentPrivileges);
    flippedPrivileges = currentPrivileges ^ mask;
    WriteQword(pTokenPrivilege + g_KernelOffsets.Present, flippedPrivileges);
}


VOID FlipEnabledBit(ULONG64 pTokenPrivilege, ULONG64 mask)
{
    ULONG64 currentPrivileges;
    ULONG64 flippedPrivileges;

    ReadQword(pTokenPrivilege + g_KernelOffsets.Enabled, &currentPrivileges);
    flippedPrivileges = currentPrivileges ^ mask;
    WriteQword(pTokenPrivilege + g_KernelOffsets.Enabled, flippedPrivileges);
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


std::string GetFileName(ULONG64 pEprocess)
{
    std::string fileName;
    ULONG64 pImageFilePointer = 0ULL;
    UNICODE_STRING unicodeString = { 0 };
    ULONG nFileNameOffset = IsPtr64() ? 0x58UL : 0x30UL; // ntdll!_FILE_OBJECT.FileName
    ULONG cb = 0UL;

    if (ReadPtr(pEprocess + g_KernelOffsets.ImageFilePointer, &pImageFilePointer))
        return std::string("");

    if (ReadMemory(pImageFilePointer + nFileNameOffset,
        &unicodeString,
        sizeof(UNICODE_STRING),
        &cb))
    {
        fileName = ReadUnicodeString((ULONG64)unicodeString.Buffer, unicodeString.Length);
    }

    return fileName;
}


std::string GetImageFileName(ULONG64 pEprocess)
{
    return ReadAnsiString(pEprocess + g_KernelOffsets.ImageFileName, 16);
}


std::string GetProcessName(ULONG64 pEprocess)
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


ULONG64 GetTokenPointer(ULONG64 pEprocess)
{
    ULONG64 pTokenPrivilege;
    ReadPtr(pEprocess + g_KernelOffsets.Token, &pTokenPrivilege);

    if (IsPtr64())
        pTokenPrivilege &= 0xFFFFFFFFFFFFFFF0ULL;
    else
        pTokenPrivilege &= 0xFFFFFFF8UL;

    pTokenPrivilege += g_KernelOffsets.Privileges;

    return pTokenPrivilege;
}


BOOL IsEnabled(ULONG64 pTokenPrivilege, ULONG64 mask)
{
    ULONG64 current;
    ReadQword(pTokenPrivilege + g_KernelOffsets.Enabled, &current);

    if (mask == MASK_ALL)
        return (current == MASK_ALL);
    else
        return ((current & mask) != 0);
}


BOOL IsPresent(ULONG64 pTokenPrivilege, ULONG64 mask)
{
    ULONG64 current;
    ReadQword(pTokenPrivilege + g_KernelOffsets.Present, &current);

    if (mask == MASK_ALL)
        return (current == MASK_ALL);
    else
        return ((current & mask) != 0);
}


std::map<ULONG_PTR, PROCESS_CONTEXT> ListProcessInformation()
{
    std::map<ULONG_PTR, PROCESS_CONTEXT> results;
    ULONG64 value;
    ULONG64 pCurrent = g_SystemProcess;
    std::string processName;
    PROCESS_CONTEXT context = { 0 };
    ULONG_PTR uniqueProcessId = 0;
    ULONG cb = 0UL;
    size_t len = 0;

    do
    {
        context = { 0 };

        if (!ReadPtr(pCurrent + g_KernelOffsets.UniqueProcessId, &value))
        {
            uniqueProcessId = (ULONG_PTR)value;
            context.Eprocess = pCurrent;
            processName = GetProcessName(pCurrent);
            len = (processName.length() > 255) ? 255 : processName.length();

            if (len == 0)
            {
                uniqueProcessId = 0;
                processName = std::string("Idle");
                len = processName.length();
                context.Token = 0ULL;
                context.Privileges = 0ULL;
            }
            else
            {
                ReadPtr(pCurrent + g_KernelOffsets.Token, &context.Token);

                if (IsPtr64())
                    context.Token &= 0xFFFFFFFFFFFFFFF0ULL;
                else
                    context.Token &= 0xFFFFFFF8UL;

                context.Privileges = context.Token + g_KernelOffsets.Privileges;
            }

            ::strcpy_s(context.ProcessName, (rsize_t)&len, processName.c_str());

            if (results.find(uniqueProcessId) == results.end())
                results[uniqueProcessId] = context;
            else
                break;

            if (!ReadPtr(pCurrent + g_KernelOffsets.ActiveProcessLinks, &value))
                pCurrent = value - g_KernelOffsets.ActiveProcessLinks;
            else
                break;
        }
        else
        {
            break;
        }
    } while (pCurrent != g_SystemProcess);

    return results;
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


BOOL RemoveEnabled(ULONG64 pTokenPrivilege, ULONG64 mask)
{
    ULONG64 current;
    ULONG64 privMask = MASK_ALL ^ mask;
    ReadQword(pTokenPrivilege + g_KernelOffsets.Enabled, &current);

    return WriteQword(pTokenPrivilege + g_KernelOffsets.Enabled, current & privMask);
}


BOOL RemovePresent(ULONG64 pTokenPrivilege, ULONG64 mask)
{
    ULONG64 current;
    ULONG64 privMask = MASK_ALL ^ mask;
    ReadQword(pTokenPrivilege + g_KernelOffsets.Present, &current);

    return WriteQword(pTokenPrivilege + g_KernelOffsets.Present, current & privMask);
}


BOOL SetEnabled(ULONG64 pTokenPrivilege, ULONG64 mask)
{
    ULONG64 current;
    ReadQword(pTokenPrivilege + g_KernelOffsets.Enabled, &current);

    return WriteQword(pTokenPrivilege + g_KernelOffsets.Enabled, current | mask);
}


BOOL SetPresent(ULONG64 pTokenPrivilege, ULONG64 mask)
{
    ULONG64 current;
    ReadQword(pTokenPrivilege + g_KernelOffsets.Present, &current);

    return WriteQword(pTokenPrivilege + g_KernelOffsets.Present, current | mask);
}
