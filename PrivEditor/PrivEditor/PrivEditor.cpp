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

BOOL g_IsInitialized = FALSE;
ULONG64 g_SystemProcess = 0ULL;
KERNEL_OFFSETS g_KernelOffsets = { 0 };

VOID WinDbgExtensionDllInit(
    PWINDBG_EXTENSION_APIS lpExtensionApis,
    USHORT /* MajorVersion */,
    USHORT /* MinorVersion */
)
{
    ULONG64 pKthread = 0ULL;
    ULONG64 pApcState = 0ULL;
    ULONG nApcStateOffset = 0UL;
    ULONG nProcessOffset = 0UL;
    PCSTR reminder = new CHAR[MAX_PATH];
    ExtensionApis = *lpExtensionApis;

    do
    {
        if (!GetExpressionEx("nt!KiInitialThread", &pKthread, &reminder))
            break;

        if (GetFieldOffset("nt!_KTHREAD", "ApcState", &nApcStateOffset) != 0UL)
            break;

        if (GetFieldOffset("nt!_KAPC_STATE", "Process", &nProcessOffset) != 0UL)
            break;

        if (GetFieldOffset("nt!_EPROCESS", "UniqueProcessId", &g_KernelOffsets.UniqueProcessId) != 0UL)
            break;

        if (GetFieldOffset("nt!_EPROCESS", "ActiveProcessLinks", &g_KernelOffsets.ActiveProcessLinks) != 0UL)
            break;

        if (GetFieldOffset("nt!_EPROCESS", "ImageFilePointer", &g_KernelOffsets.ImageFilePointer) != 0UL)
            break;

        if (GetFieldOffset("nt!_EPROCESS", "ImageFileName", &g_KernelOffsets.ImageFileName) != 0UL)
            break;

        if (GetFieldOffset("nt!_EPROCESS", "Token", &g_KernelOffsets.Token) != 0UL)
            break;

        if (GetFieldOffset("nt!_TOKEN", "Privileges", &g_KernelOffsets.Privileges) != 0UL)
            break;

        if (GetFieldOffset("nt!_SEP_TOKEN_PRIVILEGES", "Present", &g_KernelOffsets.Present) != 0UL)
            break;

        if (GetFieldOffset("nt!_SEP_TOKEN_PRIVILEGES", "Enabled", &g_KernelOffsets.Enabled) != 0UL)
            break;

        if (GetFieldOffset("nt!_SEP_TOKEN_PRIVILEGES", "EnabledByDefault", &g_KernelOffsets.EnabledByDefault) != 0UL)
            break;

        if (ReadPtr(pKthread + nApcStateOffset, &pApcState))
            break;

        ReadPtr(pApcState + nProcessOffset, &g_SystemProcess);
    } while (FALSE);

    g_IsInitialized = IsKernelAddress(g_SystemProcess) ? TRUE : FALSE;

    dprintf("\n");

    if (g_IsInitialized)
    {
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
    }
    else
    {
        dprintf("[!] This extension supports kernel mode debugger only.\n");
    }

    dprintf("\n");
}


DECLARE_API(addpriv)
{
    std::map<ULONG_PTR, PROCESS_CONTEXT> processList;
    std::smatch matches;
    ULONG_PTR pid;
    std::string priv;
    ULONG64 mask;
    std::string cmdline(args);
    std::regex re_help(R"(\s*(help|/\?)*\s*)");
    std::regex re_expected(R"(^(\d+)\s+([a-zA-Z]+)\s*$)");

    dprintf("\n");

    do
    {
        if (!g_IsInitialized)
        {
            dprintf("[-] Extension is not initialized.\n");
            dprintf("[!] This extension supports kernel mode debugger only.\n");
            break;
        }

        if (std::regex_match(cmdline, matches, re_help))
        {
            dprintf("!addpriv - Add privilege(s) to a process.\n");
            dprintf("\n");
            dprintf("Usage : !addpriv <PID> <Privilege>\n");
            dprintf("\n");
            dprintf("    PID       : Specifies target process ID.\n");
            PrintPrivileges();
            break;
        }

        if (std::regex_match(cmdline, matches, re_expected))
        {
            pid = (ULONG_PTR)std::stoull(matches[1].str());
            priv = matches[2].str();
        }
        else
        {
            dprintf("[!] Invalid arguments. See \"!addpriv help\" or \"!addpriv /?\".\n");
            break;
        }

        processList = ListProcessInformation();

        if (processList.find(pid) == processList.end())
        {
            dprintf("[-] Specified process is not found.\n");
            break;
        }

        mask = GetPrivilegeMask(priv);

        if (mask == 0xdeadbeefdeadbeefULL)
        {
            dprintf("[-] Requested privilege is invalid.\n");
            break;
        }

        if (IsPresent(processList[pid].Privileges, mask))
        {
            if (mask == MASK_ALL)
                dprintf("[*] All privileges are already present.\n");
            else
                dprintf("[*] %s is already present.\n", GetPrivilegeName(mask).c_str());

            break;
        }

        if (mask == MASK_ALL)
            dprintf("[>] Trying to add all privileges.\n");
        else
            dprintf("[>] Trying to add %s.\n", GetPrivilegeName(mask).c_str());

        SetPresent(processList[pid].Privileges, mask);

        dprintf("[*] Done.\n");
    } while (FALSE);

    dprintf("\n");
}


DECLARE_API(disableall)
{
    std::map<ULONG_PTR, PROCESS_CONTEXT> processList;
    std::smatch matches;
    ULONG_PTR pid;
    std::string cmdline(args);
    std::regex re_help(R"(\s*(help|/\?)*\s*)");
    std::regex re_expected(R"(^\s*(\d+)\s*$)");

    dprintf("\n");

    do
    {
        if (!g_IsInitialized)
        {
            dprintf("[-] Extension is not initialized.\n");
            dprintf("[!] This extension supports kernel mode debugger only.\n");
            break;
        }

        if (std::regex_match(cmdline, matches, re_help))
        {
            dprintf("!disableall - Disable all privileges available to a process.\n");
            dprintf("\n");
            dprintf("Usage : !disableall <PID>\n");
            dprintf("\n");
            dprintf("    PID : Specifies target process ID.\n");
            break;
        }

        if (std::regex_match(cmdline, matches, re_expected))
        {
            pid = (ULONG_PTR)std::stoull(matches[1].str());
        }
        else
        {
            dprintf("[!] Invalid arguments. See \"!disableall help\" or \"!disableall /?\".\n");
            break;
        }

        processList = ListProcessInformation();

        if (processList.find(pid) == processList.end())
        {
            dprintf("[-] Specified process is not found.\n");
            break;
        }

        dprintf("[>] Trying to disable all available privileges.\n");
        DisableAllAvailable(processList[pid].Privileges);

        dprintf("[*] Done.\n");
    } while (FALSE);

    dprintf("\n");
}


DECLARE_API(disablepriv)
{
    std::map<ULONG_PTR, PROCESS_CONTEXT> processList;
    ULONG_PTR pid;
    std::string priv;
    ULONG64 mask;
    std::string cmdline(args);
    std::regex re_help(R"(\s*(help|/\?)*\s*)");
    std::regex re_expected(R"(^(\d+)\s+([a-zA-Z]+)\s*$)");
    std::smatch matches;

    dprintf("\n");

    do
    {
        if (!g_IsInitialized)
        {
            dprintf("[-] Extension is not initialized.\n");
            dprintf("[!] This extension supports kernel mode debugger only.\n");
            break;
        }

        if (std::regex_match(cmdline, matches, re_help))
        {
            dprintf("!disablepriv - Disable privilege(s) of a process.\n");
            dprintf("\n");
            dprintf("Usage : !disablepriv <PID> <Privilege>\n");
            dprintf("\n");
            dprintf("    PID       : Specifies target process ID.\n");
            PrintPrivileges();
            break;
        }

        if (std::regex_match(cmdline, matches, re_expected))
        {
            pid = (ULONG_PTR)std::stoull(matches[1].str());
            priv = matches[2].str();
        }
        else {
            dprintf("[!] Invalid arguments. See \"!disablepriv help\" or \"!disablepriv help\".\n");
            break;
        }

        processList = ListProcessInformation();

        if (processList.find(pid) == processList.end())
        {
            dprintf("[-] Specified process is not found.\n");
            break;
        }

        mask = GetPrivilegeMask(priv);

        if (mask == 0xdeadbeefdeadbeefULL)
        {
            dprintf("[-] Requested privilege is invalid.\n");
            break;
        }

        if (mask == MASK_ALL)
            dprintf("[>] Trying to disable all privileges.\n");
        else
            dprintf("[>] Trying to disable %s.\n", GetPrivilegeName(mask).c_str());

        RemoveEnabled(processList[pid].Privileges, mask);

        dprintf("[*] Done.\n");
    } while (FALSE);

    dprintf("\n");
}


DECLARE_API(enableall)
{
    std::map<ULONG_PTR, PROCESS_CONTEXT> processList;
    std::smatch matches;
    ULONG_PTR pid;
    std::string cmdline(args);
    std::regex re_help(R"(\s*(help|/\?)*\s*)");
    std::regex re_expected(R"(^\s*(\d+)\s*$)");

    dprintf("\n");

    do
    {
        if (!g_IsInitialized)
        {
            dprintf("[-] Extension is not initialized.\n");
            dprintf("[!] This extension supports kernel mode debugger only.\n");
            break;
        }

        if (std::regex_match(cmdline, matches, re_help))
        {
            dprintf("!enableall - Enable all privileges available to a process.\n");
            dprintf("\n");
            dprintf("Usage : !enableall <PID>\n");
            dprintf("\n");
            dprintf("    PID       : Specifies target process ID.\n");
            break;
        }

        if (std::regex_match(cmdline, matches, re_expected))
        {
            pid = (ULONG_PTR)std::stoull(matches[1].str());
        }
        else
        {
            dprintf("[!] Invalid arguments. See \"!enableall help\" or \"!enableall /?\".\n");
            break;
        }

        processList = ListProcessInformation();

        if (processList.find(pid) == processList.end())
        {
            dprintf("[-] Specified process is not found.\n");
            break;
        }

        dprintf("[>] Trying to enable all available privileges.\n");

        EnableAllAvailable(processList[pid].Privileges);

        dprintf("[*] Done.\n");
    } while (FALSE);

    dprintf("\n");
}


DECLARE_API(enablepriv)
{
    std::map<ULONG_PTR, PROCESS_CONTEXT> processList;
    std::smatch matches;
    ULONG_PTR pid;
    std::string priv;
    ULONG64 mask;
    std::string cmdline(args);
    std::regex re_help(R"(\s*(help|/\?)*\s*)");
    std::regex re_expected(R"(^(\d+)\s+([a-zA-Z]+)\s*$)");

    dprintf("\n");

    do
    {
        if (!g_IsInitialized)
        {
            dprintf("[-] Extension is not initialized.\n");
            dprintf("[!] This extension supports kernel mode debugger only.\n");
            break;
        }

        if (std::regex_match(cmdline, matches, re_help))
        {
            dprintf("!enablepriv - Enable privilege(s) of a process.\n");
            dprintf("\n");
            dprintf("Usage : !enablepriv <PID> <Privilege>\n");
            dprintf("\n");
            dprintf("    PID       : Specifies target process ID.\n");
            PrintPrivileges();
            break;
        }

        if (std::regex_match(cmdline, matches, re_expected))
        {
            pid = (ULONG_PTR)std::stoull(matches[1].str());
            priv = matches[2].str();
        }
        else
        {
            dprintf("[!] Invalid arguments. See \"!enablepriv help\" or \"!enablepriv /?\".\n");
            break;
        }

        processList = ListProcessInformation();

        if (processList.find(pid) == processList.end())
        {
            dprintf("[-] Specified process is not found.\n");
            break;
        }

        mask = GetPrivilegeMask(priv);

        if (mask == 0xdeadbeefdeadbeefULL)
        {
            dprintf("[-] Requested privilege is invalid.\n");
            break;
        }

        if (!IsPresent(processList[pid].Privileges, mask))
        {
            if (mask == MASK_ALL)
            {
                dprintf("[*] Not all privileges are present.\n");
                dprintf("[>] Trying to add all privileges.\n");
            }
            else
            {
                dprintf("[*] %s is not present.\n", GetPrivilegeName(mask).c_str());
                dprintf("[>] Trying to add %s.\n", GetPrivilegeName(mask).c_str());
            }

            SetPresent(processList[pid].Privileges, mask);
        }

        if (IsEnabled(processList[pid].Privileges, mask))
        {
            if (mask == MASK_ALL)
                dprintf("[*] All privileges are already enabled.\n");
            else
                dprintf("[*] %s is already enabled.\n", GetPrivilegeName(mask).c_str());

            break;
        }

        if (mask == MASK_ALL)
            dprintf("[>] Trying to enable all privileges.\n");
        else
            dprintf("[>] Trying to enable %s.\n", GetPrivilegeName(mask).c_str());

        SetEnabled(processList[pid].Privileges, mask);

        dprintf("[*] Done.\n");
    } while (FALSE);

    dprintf("\n");
}


DECLARE_API(getpriv)
{
    std::map<ULONG_PTR, PROCESS_CONTEXT> processList;
    std::smatch matches;
    ULONG_PTR pid;
    std::vector<ULONG64> masks;
    std::string cmdline(args);
    std::regex re_help(R"(\s*(help|/\?)*\s*)");
    std::regex re_expected(R"(^\s*(\d+)\s*$)");

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

    do
    {
        if (!g_IsInitialized)
        {
            dprintf("[-] Extension is not initialized.\n");
            dprintf("[!] This extension supports kernel mode debugger only.\n");
            break;
        }

        if (std::regex_match(cmdline, matches, re_help))
        {
            dprintf("!getpriv - List privileges of a process.\n");
            dprintf("\n");
            dprintf("Usage : !getpriv <PID>\n");
            dprintf("\n");
            dprintf("    PID : Specifies target process ID.\n");
            break;
        }

        if (std::regex_match(cmdline, matches, re_expected))
        {
            pid = (ULONG_PTR)std::stoull(matches[1].str());
        }
        else
        {
            dprintf("[!] Invalid arguments. See \"!getpriv help\" or \"!getpriv /?\".\n");
            break;
        }

        if (pid == 0) {
            dprintf("[-] System Idle Process (PID : 0) has no token.\n");
            break;
        }

        processList = ListProcessInformation();

        if (processList.find(pid) == processList.end())
        {
            dprintf("[-] Specified process is not found.\n");
            break;
        }

        dprintf("Privilege Name                             State\n");
        dprintf("========================================== ========\n");

        for (ULONG64 mask : masks)
        {
            if (IsPresent(processList[pid].Privileges, mask))
                dprintf("%-42s %s\n", GetPrivilegeName(mask).c_str(), IsEnabled(processList[pid].Privileges, mask) ? "Enabled" : "Disabled");
        }

        dprintf("\n");

        dprintf("[*] PID                      : %d\n", pid);
        dprintf("[*] Process Name             : %s\n", processList[pid].ProcessName);
        dprintf("[*] nt!_EPROCESS             : %s\n", PointerToString(processList[pid].Eprocess).c_str());
        dprintf("[*] nt!_SEP_TOKEN_PRIVILEGES : %s\n", PointerToString(processList[pid].Privileges).c_str());
    } while (FALSE);

    dprintf("\n");
}


DECLARE_API(getps)
{
    std::map<ULONG_PTR, PROCESS_CONTEXT> processList;
    std::map<ULONG_PTR, PROCESS_CONTEXT> filteredList;
    std::smatch matches;
    std::string filter;
    std::string cmdline(args);
    std::regex re_help(R"(\s*(help|/\?)\s*)");
    std::regex re_expected(R"(^([\S ]+)$)");

    dprintf("\n");

    do
    {
        if (!g_IsInitialized)
        {
            dprintf("[-] Extension is not initialized.\n");
            dprintf("[!] This extension supports kernel mode debugger only.\n");
            break;
        }

        if (std::regex_match(cmdline, matches, re_help))
        {
            dprintf("!getps - List processes in target system.\n");
            dprintf("\n");
            dprintf("Usage : !getps [Process Name]\n");
            dprintf("\n");
            dprintf("    Process Name : (OPTIONAL) Specifies filter string for process name.\n");
            break;
        }

        if (std::regex_match(cmdline, matches, re_expected))
            filter = matches[1].str();

        processList = ListProcessInformation();

        for (std::pair<ULONG_PTR, PROCESS_CONTEXT> proc : processList)
        {
            if (_strnicmp(filter.c_str(), proc.second.ProcessName, filter.size()) == 0)
                filteredList[proc.first] = proc.second;
        }

        if (filteredList.size() > 0)
        {
            if (IsPtr64())
            {
                dprintf("     PID        nt!_EPROCESS nt!_SEP_TOKEN_PRIVILEGES Process Name\n");
                dprintf("======== =================== ======================== ============\n");
            }
            else
            {
                dprintf("     PID nt!_EPROCESS nt!_SEP_TOKEN_PRIVILEGES Process Name\n");
                dprintf("======== ============ ======================== ============\n");
            }

            for (std::pair<ULONG_PTR, PROCESS_CONTEXT> proc : filteredList)
            {
                if (IsPtr64())
                {
                    dprintf("%8d %19s %24s %s\n",
                        proc.first,
                        PointerToString(proc.second.Eprocess).c_str(),
                        PointerToString(proc.second.Privileges).c_str(),
                        proc.second.ProcessName);
                }
                else
                {
                    dprintf("%8d %12s %24s %s\n",
                        proc.first,
                        PointerToString(proc.second.Eprocess).c_str(),
                        PointerToString(proc.second.Privileges).c_str(),
                        proc.second.ProcessName);
                }
            }
        }
        else
        {
            dprintf("[-] No entries.\n");
        }
    } while (FALSE);

    dprintf("\n");
}


DECLARE_API(rmpriv)
{
    std::map<ULONG_PTR, PROCESS_CONTEXT> processList;
    std::smatch matches;
    ULONG_PTR pid;
    std::string priv;
    ULONG64 mask;
    std::string cmdline(args);
    std::regex re_help(R"(\s*(help|/\?)*\s*)");
    std::regex re_expected(R"(^(\d+)\s+([a-zA-Z]+)\s*$)");

    dprintf("\n");

    do
    {
        if (!g_IsInitialized)
        {
            dprintf("[-] Extension is not initialized.\n");
            dprintf("[!] This extension supports kernel mode debugger only.\n");
            break;
        }

        if (std::regex_match(cmdline, matches, re_help))
        {
            dprintf("!rmpriv - Remove privilege(s) from a process.\n");
            dprintf("\n");
            dprintf("Usage : !rmpriv <PID> <Privilege>\n");
            dprintf("\n");
            dprintf("    PID       : Specifies target process ID.\n");
            PrintPrivileges();
            break;
        }

        if (std::regex_match(cmdline, matches, re_expected))
        {
            pid = (ULONG_PTR)std::stoull(matches[1].str());
            priv = matches[2].str();
        }
        else
        {
            dprintf("[!] Invalid arguments. See \"!rmpriv help\" or \"!rmpriv /?\".\n");
            break;
        }

        processList = ListProcessInformation();

        if (processList.find(pid) == processList.end())
        {
            dprintf("[-] Specified process is not found.\n");
            break;
        }

        mask = GetPrivilegeMask(priv);

        if (mask == 0xdeadbeefdeadbeefULL)
        {
            dprintf("[-] Requested privilege is invalid.\n");
            break;
        }

        if (mask == MASK_ALL)
            dprintf("[>] Trying to remove all privileges.\n");
        else
            dprintf("[>] Trying to remove %s.\n", GetPrivilegeName(mask).c_str());

        RemovePresent(processList[pid].Privileges, mask);

        dprintf("[*] Done.\n");
    } while (FALSE);

    dprintf("\n");
}
