#pragma once

BOOL DisableAllAvailable(ULONG64 pTokenPrivilege);
BOOL EnableAllAvailable(ULONG64 pTokenPrivilege);
VOID FlipPresentBit(ULONG64 pTokenPrivilege, ULONG64 mask);
VOID FlipEnabledBit(ULONG64 pTokenPrivilege, ULONG64 mask);
ULONG64 GetPrivilegeMask(std::string priv);
std::string GetPrivilegeName(ULONG64 mask);
std::string GetProcessName(ULONG64 pEprocess);
BOOL IsEnabled(ULONG64 pTokenPrivilege, ULONG64 mask);
BOOL IsPresent(ULONG64 pTokenPrivilege, ULONG64 mask);
std::map<ULONG_PTR, PROCESS_CONTEXT> ListProcessInformation();
VOID PrintPrivileges();
BOOL RemoveEnabled(ULONG64 pTokenPrivilege, ULONG64 mask);
BOOL RemovePresent(ULONG64 pTokenPrivilege, ULONG64 mask);
ULONG64 GetTokenPointer(ULONG64 pEprocess);
BOOL SetEnabled(ULONG64 pTokenPrivilege, ULONG64 mask);
BOOL SetPresent(ULONG64 pTokenPrivilege, ULONG64 mask);
