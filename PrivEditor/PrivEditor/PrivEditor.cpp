#include "pch.h"
#include "PrivEditor.h"
#include "utils.h"
#include "helpers.h"

EXT_API_VERSION ApiVersion = {
    0,                        // MajorVersion
    0,                        // MinorVersion
    EXT_API_VERSION_NUMBER64, // Revision
    0                         // Reserved
};

WINDBG_EXTENSION_APIS ExtensionApis;

LPEXT_API_VERSION ExtensionApiVersion(void)
{
    return &ApiVersion;
}


VOID WinDbgExtensionDllInit(
    PWINDBG_EXTENSION_APIS lpExtensionApis,
    USHORT MajorVersion,
    USHORT MinorVersion
)
{
    ExtensionApis = *lpExtensionApis;

    dprintf("\n");

    if (Initialize()) {
        dprintf("PrivEditor - Kernel Mode WinDbg extension for token privilege edit.\n");
        dprintf("\n");
        dprintf("Commands :\n");
        dprintf("    + !getps       : List processes in target system.\n");
        dprintf("    + !getpriv     : List privileges of a process.\n");
        dprintf("    + !addpriv     : Add privilege(s) to a process.\n");
        dprintf("    + !rmpriv      : Remove privilege(s) from a process.\n");
        dprintf("    + !enablepriv  : Enable privilege(s) of a process.\n");
        dprintf("    + !disablepriv : Disable privilege(s) of a process.\n");
        dprintf("    + !enableall   : Enable all privileges available to a process.\n");
        dprintf("    + !disableall  : Disable all privileges available to a process.\n");
        dprintf("\n");
        dprintf("[*] To see command help, execute \"!<Command> help\" or \"!<Command> /?\".\n");
        dprintf("\n");
    }
    else {
        dprintf("[-] Failed to initialize.\n");
        dprintf("[!] This extension supports kernel mode debugger only.\n\n");
    }
    // PrintDebugInfo();
}


DECLARE_API(addpriv)
{
    std::string cmdline(args);
    std::regex re_help(R"(\s*(help|/\?)*\s*)");
    std::regex re_expected(R"(^(\d+)\s+([a-zA-Z]+)\s*$)");
    std::smatch matches;
    ULONG_PTR pid;
    std::string priv;
    ULONG_PTR pTokenPrivilege;
    ULONG64 mask;

    dprintf("\n");

    if (!IsInitialized()) {
        dprintf("[-] Extension is not initialized.\n");
        dprintf("[!] This extension supports kernel mode debugger only.\n\n");
        return;
    }

    if (std::regex_match(cmdline, matches, re_help)) {
        dprintf("!addpriv - Add privilege(s) to a process.\n\n");
        dprintf("Usage : !addpriv <PID> <Privilege>\n\n");
        dprintf("    PID       : Specifies target process ID.\n");
        PrintPrivileges();
        return;
    }

    if (std::regex_match(cmdline, matches, re_expected)) {
        pid = (ULONG_PTR)std::stoull(matches[1].str());
        priv = matches[2].str();
    }
    else {
        dprintf("[!] Invalid arguments. See \"!addpriv help\" or \"!addpriv /?\".\n\n");
        return;
    }

    std::map<ULONG_PTR, ULONG_PTR> processList = ListEprocess();

    if (processList.find(pid) == processList.end()) {
        dprintf("[-] Failed to search target PID.\n\n");
        return;
    }

    pTokenPrivilege = GetTokenPointer(processList[pid]);

    if (!IsKernelAddress(pTokenPrivilege)) {
        dprintf("[-] Failed to get _SEP_TOKEN_PRIVILEGES pointer.\n\n");
        return;
    }

    mask = GetPrivilegeMask(priv);

    if (mask == 0xdeadbeefdeadbeefULL) {
        dprintf("[-] Requested privilege is invalid.\n\n");
        return;
    }

    if (IsPresent(pTokenPrivilege, mask)) {
        if (mask == MASK_ALL)
            dprintf("[*] All privileges are already present.\n\n");
        else
            dprintf("[*] %s is already present.\n\n", GetPrivilegeName(mask).c_str());
        return;
    }

    if (mask == MASK_ALL)
        dprintf("[>] Trying to add all privileges.\n");
    else
        dprintf("[>] Trying to add %s.\n", GetPrivilegeName(mask).c_str());

    SetPresent(pTokenPrivilege, mask);
    dprintf("[*] Completed.\n\n");
}


DECLARE_API(disableall)
{
    std::string cmdline(args);
    std::regex re_help(R"(\s*(help|/\?)*\s*)");
    std::regex re_expected(R"(^\s*(\d+)\s*$)");
    std::smatch matches;
    ULONG_PTR pid;
    ULONG_PTR pTokenPrivilege;

    dprintf("\n");

    if (!IsInitialized()) {
        dprintf("[-] Extension is not initialized.\n");
        dprintf("[!] This extension supports kernel mode debugger only.\n\n");
        return;
    }

    if (std::regex_match(cmdline, matches, re_help)) {
        dprintf("!disableall - Disable all privileges available to a process.\n\n");
        dprintf("Usage : !disableall <PID>\n\n");
        dprintf("    PID : Specifies target process ID.\n\n");
        return;
    }

    if (std::regex_match(cmdline, matches, re_expected)) {
        pid = (ULONG_PTR)std::stoull(matches[1].str());
    }
    else {
        dprintf("[!] Invalid arguments. See \"!disableall help\" or \"!disableall /?\".\n\n");
        return;
    }

    std::map<ULONG_PTR, ULONG_PTR> processList = ListEprocess();

    if (processList.find(pid) == processList.end()) {
        dprintf("[-] Failed to search target PID.\n\n");
        return;
    }

    pTokenPrivilege = GetTokenPointer(processList[pid]);

    if (!IsKernelAddress(pTokenPrivilege)) {
        dprintf("[-] Failed to get _SEP_TOKEN_PRIVILEGES pointer.\n\n");
        return;
    }

    dprintf("[>] Trying to disable all available privileges.\n");
    DisableAllAvailable(pTokenPrivilege);
    dprintf("[*] Completed.\n\n");
}


DECLARE_API(disablepriv)
{
    std::string cmdline(args);
    std::regex re_help(R"(\s*(help|/\?)*\s*)");
    std::regex re_expected(R"(^(\d+)\s+([a-zA-Z]+)\s*$)");
    std::smatch matches;
    ULONG_PTR pid;
    std::string priv;
    ULONG_PTR pTokenPrivilege;
    ULONG64 mask;

    dprintf("\n");

    if (!IsInitialized()) {
        dprintf("[-] Extension is not initialized.\n");
        dprintf("[!] This extension supports kernel mode debugger only.\n\n");
        return;
    }

    if (std::regex_match(cmdline, matches, re_help)) {
        dprintf("!disablepriv - Disable privilege(s) of a process.\n\n");
        dprintf("Usage : !disablepriv <PID> <Privilege>\n\n");
        dprintf("    PID       : Specifies target process ID.\n");
        PrintPrivileges();
        return;
    }

    if (std::regex_match(cmdline, matches, re_expected)) {
        pid = (ULONG_PTR)std::stoull(matches[1].str());
        priv = matches[2].str();
    }
    else {
        dprintf("[!] Invalid arguments. See \"!disablepriv help\" or \"!disablepriv help\".\n\n");
        return;
    }

    std::map<ULONG_PTR, ULONG_PTR> processList = ListEprocess();

    if (processList.find(pid) == processList.end()) {
        dprintf("[-] Failed to search target PID.\n\n");
        return;
    }

    pTokenPrivilege = GetTokenPointer(processList[pid]);

    if (!IsKernelAddress(pTokenPrivilege)) {
        dprintf("[-] Failed to get _SEP_TOKEN_PRIVILEGES pointer.\n\n");
        return;
    }

    mask = GetPrivilegeMask(priv);

    if (mask == 0xdeadbeefdeadbeefULL) {
        dprintf("[-] Requested privilege is invalid.\n\n");
        return;
    }

    if (mask == MASK_ALL)
        dprintf("[>] Trying to disable all privileges.\n");
    else
        dprintf("[>] Trying to disable %s.\n", GetPrivilegeName(mask).c_str());
    
    RemoveEnabled(pTokenPrivilege, mask);
    dprintf("[*] Completed.\n\n");
}


DECLARE_API(enableall)
{
    std::string cmdline(args);
    std::regex re_help(R"(\s*(help|/\?)*\s*)");
    std::regex re_expected(R"(^\s*(\d+)\s*$)");
    std::smatch matches;
    ULONG_PTR pid;
    ULONG_PTR pTokenPrivilege;

    dprintf("\n");

    if (!IsInitialized()) {
        dprintf("[-] Extension is not initialized.\n");
        dprintf("[!] This extension supports kernel mode debugger only.\n\n");
        return;
    }

    if (std::regex_match(cmdline, matches, re_help)) {
        dprintf("!enableall - Enable all privileges available to a process.\n\n");
        dprintf("Usage : !enableall <PID>\n\n");
        dprintf("    PID       : Specifies target process ID.\n\n");
        return;
    }

    if (std::regex_match(cmdline, matches, re_expected)) {
        pid = (ULONG_PTR)std::stoull(matches[1].str());
    }
    else {
        dprintf("[!] Invalid arguments. See \"!enableall help\" or \"!enableall /?\".\n\n");
        return;
    }

    std::map<ULONG_PTR, ULONG_PTR> processList = ListEprocess();

    if (processList.find(pid) == processList.end()) {
        dprintf("[-] Failed to search target PID.\n\n");
        return;
    }

    pTokenPrivilege = GetTokenPointer(processList[pid]);

    if (!IsKernelAddress(pTokenPrivilege)) {
        dprintf("[-] Failed to get _SEP_TOKEN_PRIVILEGES pointer.\n\n");
        return;
    }

    dprintf("[>] Trying to enable all available privileges.\n");
    EnableAllAvailable(pTokenPrivilege);
    dprintf("[*] Completed.\n\n");
}


DECLARE_API(enablepriv)
{
    std::string cmdline(args);
    std::regex re_help(R"(\s*(help|/\?)*\s*)");
    std::regex re_expected(R"(^(\d+)\s+([a-zA-Z]+)\s*$)");
    std::smatch matches;
    ULONG_PTR pid;
    std::string priv;
    ULONG_PTR pTokenPrivilege;
    ULONG64 mask;

    dprintf("\n");

    if (!IsInitialized()) {
        dprintf("[-] Extension is not initialized.\n");
        dprintf("[!] This extension supports kernel mode debugger only.\n\n");
        return;
    }

    if (std::regex_match(cmdline, matches, re_help)) {
        dprintf("!enablepriv - Enable privilege(s) of a process.\n\n");
        dprintf("Usage : !enablepriv <PID> <Privilege>\n\n");
        dprintf("    PID       : Specifies target process ID.\n");
        PrintPrivileges();
        return;
    }

    if (std::regex_match(cmdline, matches, re_expected)) {
        pid = (ULONG_PTR)std::stoull(matches[1].str());
        priv = matches[2].str();
    }
    else {
        dprintf("[!] Invalid arguments. See \"!enablepriv help\" or \"!enablepriv /?\".\n\n");
        return;
    }

    std::map<ULONG_PTR, ULONG_PTR> processList = ListEprocess();

    if (processList.find(pid) == processList.end()) {
        dprintf("[-] Failed to search target PID.\n\n");
        return;
    }

    pTokenPrivilege = GetTokenPointer(processList[pid]);

    if (!IsKernelAddress(pTokenPrivilege)) {
        dprintf("[-] Failed to get _SEP_TOKEN_PRIVILEGES pointer.\n\n");
        return;
    }

    mask = GetPrivilegeMask(priv);

    if (mask == 0xdeadbeefdeadbeefULL) {
        dprintf("[-] Requested privilege is invalid.\n\n");
        return;
    }

    if (!IsPresent(pTokenPrivilege, mask)) {
        if (mask == MASK_ALL) {
            dprintf("[*] Not all privileges are present.\n");
            dprintf("[>] Trying to add all privileges.\n");
        }
        else {
            dprintf("[*] %s is not present.\n", GetPrivilegeName(mask).c_str());
            dprintf("[>] Trying to add %s.\n", GetPrivilegeName(mask).c_str());
        }

        SetPresent(pTokenPrivilege, mask);
    }

    if (IsEnabled(pTokenPrivilege, mask)) {
        if (mask == MASK_ALL)
            dprintf("[*] All privileges are already enabled.\n\n");
        else
            dprintf("[*] %s is already enabled.\n\n", GetPrivilegeName(mask).c_str());
        return;
    }

    if (mask == MASK_ALL)
        dprintf("[>] Trying to enable all privileges.\n");
    else
        dprintf("[>] Trying to enable %s.\n", GetPrivilegeName(mask).c_str());

    SetEnabled(pTokenPrivilege, mask);
    dprintf("[*] Completed.\n\n");
}


DECLARE_API(getpriv)
{
    std::string cmdline(args);
    std::regex re_help(R"(\s*(help|/\?)*\s*)");
    std::regex re_expected(R"(^\s*(\d+)\s*$)");
    std::smatch matches;
    ULONG_PTR pid;
    ULONG_PTR pTokenPrivilege;
    std::vector<ULONG64> masks;

    masks.push_back(MASK_CREATE_TOKEN);
    masks.push_back(MASK_ASSIGN_PRIMARY_TOKEN);
    masks.push_back(MASK_LOCK_MEMORY);
    masks.push_back(MASK_INCREASE_QUOTA);
    masks.push_back(MASK_MACHINE_ACCOUNT);
    masks.push_back(MASK_TCB);
    masks.push_back(MASK_SECURITY);
    masks.push_back(MASK_TAKE_OWNERSHIP);
    masks.push_back(MASK_LOAD_DRIVER);
    masks.push_back(MASK_SYSTEM_PROFILE);
    masks.push_back(MASK_SYSTEMTIME);
    masks.push_back(MASK_PROFILE_SINGLE_PROCESS);
    masks.push_back(MASK_INCREASE_BASE_PRIORITY);
    masks.push_back(MASK_CREATE_PAGEFILE);
    masks.push_back(MASK_CREATE_PERMANENT);
    masks.push_back(MASK_BACKUP);
    masks.push_back(MASK_RESTORE);
    masks.push_back(MASK_SHUTDOWN);
    masks.push_back(MASK_DEBUG);
    masks.push_back(MASK_AUDIT);
    masks.push_back(MASK_SYSTEM_ENVIRONMENT);
    masks.push_back(MASK_CHANGE_NOTIFY);
    masks.push_back(MASK_REMOTE_SHUTDOWN);
    masks.push_back(MASK_UNDOCK);
    masks.push_back(MASK_SYNC_AGENT);
    masks.push_back(MASK_ENABLE_DELEGATION);
    masks.push_back(MASK_MANAGE_VOLUME);
    masks.push_back(MASK_IMPERSONATE);
    masks.push_back(MASK_CREATE_GLOBAL);
    masks.push_back(MASK_TRUSTED_CRED_MAN_ACCESS);
    masks.push_back(MASK_RELABEL);
    masks.push_back(MASK_INCREASE_WORKING_SET);
    masks.push_back(MASK_TIME_ZONE);
    masks.push_back(MASK_CREATE_SYMBOLIC_LINK);
    masks.push_back(MASK_DELEGATE_SESSION_USER_IMPERSONATE);

    dprintf("\n");

    if (!IsInitialized()) {
        dprintf("[-] Extension is not initialized.\n");
        dprintf("[!] This extension supports kernel mode debugger only.\n\n");
        return;
    }

    if (std::regex_match(cmdline, matches, re_help)) {
        dprintf("!getpriv - List privileges of a process.\n\n");
        dprintf("Usage : !getpriv <PID>\n\n");
        dprintf("    PID : Specifies target process ID.\n\n");
        return;
    }

    if (std::regex_match(cmdline, matches, re_expected)) {
        pid = (ULONG_PTR)std::stoull(matches[1].str());
    }
    else {
        dprintf("[!] Invalid arguments. See \"!getpriv help\" or \"!getpriv /?\".\n\n");
        return;
    }

    if (pid == 0) {
        dprintf("[-] System Idle Process (PID : 0) has no token.\n\n");
        return;
    }

    std::map<ULONG_PTR, ULONG_PTR> processList = ListEprocess();

    if (processList.find(pid) == processList.end()) {
        dprintf("[-] Failed to search target PID.\n\n");
        return;
    }

    std::string processName = GetProcessName(processList[pid]);
    pTokenPrivilege = GetTokenPointer(processList[pid]);

    if (!IsKernelAddress(pTokenPrivilege)) {
        dprintf("[-] Failed to get _SEP_TOKEN_PRIVILEGES pointer.\n\n");
        return;
    }

    dprintf("Privilege Name                             State\n");
    dprintf("========================================== ========\n");

    for (ULONG64 mask : masks) {
        if (IsPresent(pTokenPrivilege, mask))
            dprintf("%-42s %s\n", GetPrivilegeName(mask).c_str(), IsEnabled(pTokenPrivilege, mask) ? "Enabled" : "Disabled");
    }

    dprintf("\n");

    if (IsPtr64() && IsKernelAddress(pTokenPrivilege)) {
        dprintf("[*] PID                      : %d\n", pid);
        dprintf("[*] Process Name             : %s\n", processName.c_str());
        dprintf("[*] nt!_EPROCESS             : 0x%08x`%08x\n",
            (((ULONG64)processList[pid]) >> 32) & 0xffffffff,
            processList[pid] & 0xffffffff);
        dprintf("[*] nt!_SEP_TOKEN_PRIVILEGES : 0x%08x`%08x\n",
            (((ULONG64)pTokenPrivilege) >> 32) & 0xffffffff,
            pTokenPrivilege & 0xffffffff);
    }
    else if (!IsPtr64() && IsKernelAddress(pTokenPrivilege)) {
        dprintf("[*] PID                      : %d\n", pid);
        dprintf("[*] Process Name             : %s\n", processName.c_str());
        dprintf("[*] nt!_EPROCESS             : 0x%08x\n", processList[pid]);
        dprintf("[*] nt!_SEP_TOKEN_PRIVILEGES : 0x%08x\n", pTokenPrivilege);
    }
    else {
        dprintf("[-] Failed to get _SEP_TOKEN_PRIVILEGES for PID %d.\n", pid);
    }

    dprintf("\n");
}


DECLARE_API(getps)
{
    std::string cmdline(args);
    std::regex re_help(R"(\s*(help|/\?)\s*)");
    std::regex re_expected(R"(^([\S ]+)$)");
    std::smatch matches;
    std::string processName;
    std::string filter;
    ULONG_PTR pTokenPrivilege;

    dprintf("\n");

    if (!IsInitialized()) {
        dprintf("[-] Extension is not initialized.\n");
        dprintf("[!] This extension supports kernel mode debugger only.\n\n");
        return;
    }

    if (std::regex_match(cmdline, matches, re_help)) {
        dprintf("!getps - List processes in target system.\n\n");
        dprintf("Usage : !getps [Process Name]\n\n");
        dprintf("    Process Name : (OPTIONAL) Specifies filter string for process name.\n\n");
        return;
    }

    if (std::regex_match(cmdline, matches, re_expected))
        filter = matches[1].str();

    std::map<ULONG_PTR, ULONG_PTR> processList = ListEprocess();

    if (IsPtr64()) {
        dprintf("     PID        nt!_EPROCESS nt!_SEP_TOKEN_PRIVILEGES Process Name\n");
        dprintf("======== =================== ======================== ============\n");
    }
    else {
        dprintf("     PID nt!_EPROCESS nt!_SEP_TOKEN_PRIVILEGES Process Name\n");
        dprintf("======== ============ ======================== ============\n");
    }

    for (auto proc : processList) {
        if (proc.first == 0) {
            processName = std::string("System Idle Process");
            pTokenPrivilege = 0;
        }
        else {
            processName = GetProcessName(proc.second);
            pTokenPrivilege = GetTokenPointer(proc.second);
        }

        if (filter.empty()) {
            if (IsPtr64()) {
                dprintf("%8d 0x%08x`%08x      0x%08x`%08x %s\n",
                    proc.first <= 0 ? 0 : proc.first,
                    ((ULONG64)proc.second >> 32) & 0xffffffff,
                    proc.second & 0xffffffff,
                    ((ULONG64)pTokenPrivilege >> 32) & 0xffffffff,
                    pTokenPrivilege & 0xffffffff,
                    processName.c_str());
            }
            else {
                dprintf("%8d   0x%08x               0x%08x %s\n",
                    proc.first <= 0 ? 0 : proc.first,
                    proc.second,
                    pTokenPrivilege,
                    processName.c_str());
            }
        }
        else {
            if (filter.size() > processName.size())
                continue;

            if (IsPtr64() &&
                (_strnicmp(filter.c_str(), processName.c_str(), filter.size()) == 0)) {
                dprintf("%8d 0x%08x`%08x      0x%08x`%08x %s\n",
                    proc.first <= 0 ? 0 : proc.first,
                    ((ULONG64)proc.second >> 32) & 0xffffffff,
                    proc.second & 0xffffffff,
                    ((ULONG64)pTokenPrivilege >> 32) & 0xffffffff,
                    pTokenPrivilege & 0xffffffff,
                    processName.c_str());
            }
            else if (_strnicmp(filter.c_str(), processName.c_str(), filter.size()) == 0) {
                dprintf("%8d   0x%08x               0x%08x %s\n",
                    proc.first <= 0 ? 0 : proc.first,
                    proc.second,
                    pTokenPrivilege,
                    processName.c_str());
            }
        }
    }
    dprintf("\n");
}


DECLARE_API(rmpriv)
{
    std::string cmdline(args);
    std::regex re_help(R"(\s*(help|/\?)*\s*)");
    std::regex re_expected(R"(^(\d+)\s+([a-zA-Z]+)\s*$)");
    std::smatch matches;
    ULONG_PTR pid;
    std::string priv;
    ULONG_PTR pTokenPrivilege;
    ULONG64 mask;

    dprintf("\n");

    if (!IsInitialized()) {
        dprintf("[-] Extension is not initialized.\n");
        dprintf("[!] This extension supports kernel mode debugger only.\n\n");
        return;
    }

    if (std::regex_match(cmdline, matches, re_help)) {
        dprintf("!rmpriv - Remove privilege(s) from a process.\n\n");
        dprintf("Usage : !rmpriv <PID> <Privilege>\n\n");
        dprintf("    PID       : Specifies target process ID.\n");
        PrintPrivileges();
        return;
    }

    if (std::regex_match(cmdline, matches, re_expected)) {
        pid = (ULONG_PTR)std::stoull(matches[1].str());
        priv = matches[2].str();
    }
    else {
        dprintf("[!] Invalid arguments. See \"!rmpriv help\" or \"!rmpriv /?\".\n\n");
        return;
    }

    std::map<ULONG_PTR, ULONG_PTR> processList = ListEprocess();

    if (processList.find(pid) == processList.end()) {
        dprintf("[-] Failed to search target PID.\n\n");
        return;
    }

    pTokenPrivilege = GetTokenPointer(processList[pid]);

    if (!IsKernelAddress(pTokenPrivilege)) {
        dprintf("[-] Failed to get _SEP_TOKEN_PRIVILEGES pointer.\n\n");
        return;
    }

    mask = GetPrivilegeMask(priv);

    if (mask == 0xdeadbeefdeadbeefULL) {
        dprintf("[-] Requested privilege is invalid.\n\n");
        return;
    }

    if (mask == MASK_ALL)
        dprintf("[>] Trying to remove all privileges.\n");
    else
        dprintf("[>] Trying to remove %s.\n", GetPrivilegeName(mask).c_str());

    RemovePresent(pTokenPrivilege, mask);
    dprintf("[*] Completed.\n\n");
}
