#pragma once

BOOL DisableAllAvailable(ULONG_PTR pTokenPrivilege);
BOOL EnableAllAvailable(ULONG_PTR pTokenPrivilege);
VOID FlipPresentBit(ULONG_PTR pTokenPrivilege, ULONG64 mask);
VOID FlipEnabledBit(ULONG_PTR pTokenPrivilege, ULONG64 mask);
ULONG64 GetPrivilegeMask(std::string priv);
std::string GetPrivilegeName(ULONG64 mask);
std::string GetProcessName(ULONG_PTR pEprocess);
BOOL Initialize();
BOOL IsEnabled(ULONG_PTR pTokenPrivilege, ULONG64 mask);
BOOL IsInitialized();
BOOL IsPresent(ULONG_PTR pTokenPrivilege, ULONG64 mask);
std::map<ULONG_PTR, ULONG_PTR> ListEprocess();
VOID PrintDebugInfo();
VOID PrintPrivileges();
BOOL RemoveEnabled(ULONG_PTR pTokenPrivilege, ULONG64 mask);
BOOL RemovePresent(ULONG_PTR pTokenPrivilege, ULONG64 mask);
ULONG_PTR GetTokenPointer(ULONG_PTR pEprocess);
BOOL SetEnabled(ULONG_PTR pTokenPrivilege, ULONG64 mask);
BOOL SetPresent(ULONG_PTR pTokenPrivilege, ULONG64 mask);
