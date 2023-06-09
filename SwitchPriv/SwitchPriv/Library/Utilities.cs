using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using SwitchPriv.Interop;

namespace SwitchPriv.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static bool DisableSinglePrivilege(IntPtr hToken, string privName)
        {
            bool status = Helpers.GetPrivilegeLuid(privName, out LUID luid);

            if (status)
                status = DisableSinglePrivilege(hToken, luid);

            return status;
        }


        public static bool DisableSinglePrivilege(IntPtr hToken, LUID priv)
        {
            int error;
            bool status;
            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES(1);
            tp.Privileges[0].Luid = priv;
            tp.Privileges[0].Attributes = 0;
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            status = NativeMethods.AdjustTokenPrivileges(
                hToken,
                false,
                pTokenPrivilege,
                0,
                IntPtr.Zero,
                IntPtr.Zero);
            error = Marshal.GetLastWin32Error();
            status = (status && (error == 0));

            if (!status)
            {
                Console.WriteLine("[-] Failed to disable {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
            }

            return status;
        }


        public static bool EnableMultiplePrivileges(IntPtr hToken, string[] privs)
        {
            Dictionary<string, bool> results = new Dictionary<string, bool>();
            var privList = new List<string>(privs);
            bool isEnabled;
            bool enabledAll = true;
            Helpers.GetTokenPrivileges(hToken, out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

            foreach (var name in privList)
            {
                results.Add(name, false);
            }

            foreach (var priv in availablePrivs)
            {
                foreach (var name in privList)
                {
                    if (Helpers.CompareIgnoreCase(priv.Key, name))
                    {
                        isEnabled = ((priv.Value & SE_PRIVILEGE_ATTRIBUTES.ENABLED) != 0);
                        Helpers.GetPrivilegeLuid(priv.Key, out LUID luid);

                        if (isEnabled)
                            results[name] = true;
                        else
                            results[name] = EnableSinglePrivilege(hToken, luid);
                    }
                }
            }

            foreach (var result in results)
            {
                if (!result.Value)
                {
                    Console.WriteLine("[-] {0} is not available.", result.Key);
                    enabledAll = false;
                }
            }

            return enabledAll;
        }


        public static bool EnableSinglePrivilege(IntPtr hToken, string privilegeName)
        {
            bool status = NativeMethods.LookupPrivilegeValue(null, privilegeName, out LUID luid);

            if (status)
                status = EnableSinglePrivilege(hToken, luid);

            return status;
        }


        public static bool EnableSinglePrivilege(IntPtr hToken, LUID priv)
        {
            int error;
            bool status;
            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES(1);
            tp.Privileges[0].Luid = priv;
            tp.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.ENABLED;
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            status = NativeMethods.AdjustTokenPrivileges(
                hToken,
                false,
                pTokenPrivilege,
                0,
                IntPtr.Zero,
                IntPtr.Zero);
            error = Marshal.GetLastWin32Error();
            status = (status && (error == 0));

            if (!status)
            {
                Console.WriteLine("[-] Failed to enable {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
            }

            return status;
        }


        public static string GetIntegrityLevel(IntPtr hToken)
        {
            int ERROR_INSUFFICIENT_BUFFER = 122;
            StringComparison opt = StringComparison.OrdinalIgnoreCase;
            int error;
            bool status;
            int bufferLength = Marshal.SizeOf(typeof(TOKEN_PRIVILEGES));
            IntPtr pTokenIntegrity;

            do
            {
                pTokenIntegrity = Marshal.AllocHGlobal(bufferLength);
                Helpers.ZeroMemory(pTokenIntegrity, bufferLength);

                status = NativeMethods.GetTokenInformation(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                    pTokenIntegrity,
                    bufferLength,
                    out bufferLength);
                error = Marshal.GetLastWin32Error();

                if (!status)
                    Marshal.FreeHGlobal(pTokenIntegrity);
            } while (!status && (error == ERROR_INSUFFICIENT_BUFFER));

            if (!status)
                return "N/A";

            var sidAndAttrs = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                pTokenIntegrity,
                typeof(SID_AND_ATTRIBUTES));

            if (!NativeMethods.ConvertSidToStringSid(sidAndAttrs.Sid, out string strSid))
                return "N/A";

            if (string.Compare(strSid, Win32Consts.UNTRUSTED_MANDATORY_LEVEL, opt) == 0)
                return "UNTRUSTED_MANDATORY_LEVEL";
            else if (string.Compare(strSid, Win32Consts.LOW_MANDATORY_LEVEL, opt) == 0)
                return "LOW_MANDATORY_LEVEL";
            else if (string.Compare(strSid, Win32Consts.MEDIUM_MANDATORY_LEVEL, opt) == 0)
                return "MEDIUM_MANDATORY_LEVEL";
            else if (string.Compare(strSid, Win32Consts.MEDIUM_PLUS_MANDATORY_LEVEL, opt) == 0)
                return "MEDIUM_PLUS_MANDATORY_LEVEL";
            else if (string.Compare(strSid, Win32Consts.HIGH_MANDATORY_LEVEL, opt) == 0)
                return "HIGH_MANDATORY_LEVEL";
            else if (string.Compare(strSid, Win32Consts.SYSTEM_MANDATORY_LEVEL, opt) == 0)
                return "SYSTEM_MANDATORY_LEVEL";
            else if (string.Compare(strSid, Win32Consts.PROTECTED_MANDATORY_LEVEL, opt) == 0)
                return "PROTECTED_MANDATORY_LEVEL";
            else if (string.Compare(strSid, Win32Consts.SECURE_MANDATORY_LEVEL, opt) == 0)
                return "SECURE_MANDATORY_LEVEL";
            else
                return "N/A";
        }


        public static int GetParentProcessId()
        {
            return GetParentProcessId(Process.GetCurrentProcess().Handle);
        }


        public static int GetParentProcessId(IntPtr hProcess)
        {
            int ntstatus;
            var sizeInformation = Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            var buffer = Marshal.AllocHGlobal(sizeInformation);

            if (hProcess == IntPtr.Zero)
                return 0;

            ntstatus = NativeMethods.NtQueryInformationProcess(
                hProcess,
                PROCESSINFOCLASS.ProcessBasicInformation,
                buffer,
                sizeInformation,
                IntPtr.Zero);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to get process information.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(ntstatus, true));
                Marshal.FreeHGlobal(buffer);
                
                return 0;
            }

            var basicInfo = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(
                buffer,
                typeof(PROCESS_BASIC_INFORMATION));
            int ppid = basicInfo.InheritedFromUniqueProcessId.ToInt32();

            Marshal.FreeHGlobal(buffer);

            return ppid;
        }


        public static bool ImpersonateAsSmss(string[] privs)
        {
            int error;
            int smss;

            Console.WriteLine("[>] Trying to impersonate as smss.exe.");

            try
            {
                smss = (Process.GetProcessesByName("smss")[0]).Id;
            }
            catch
            {
                Console.WriteLine("[-] Failed to get process id of smss.exe.\n");

                return false;
            }

            IntPtr hProcess = NativeMethods.OpenProcess(
                ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION,
                true,
                smss);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get handle to smss.exe process.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            if (!NativeMethods.OpenProcessToken(
                hProcess,
                TokenAccessFlags.TOKEN_DUPLICATE,
                out IntPtr hToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get handle to smss.exe process token.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                NativeMethods.CloseHandle(hProcess);

                return false;
            }

            NativeMethods.CloseHandle(hProcess);

            if (!NativeMethods.DuplicateTokenEx(
                hToken,
                TokenAccessFlags.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                TOKEN_TYPE.TokenPrimary,
                out IntPtr hDupToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to duplicate smss.exe process token.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                NativeMethods.CloseHandle(hToken);

                return false;
            }

            if (!EnableMultiplePrivileges(hDupToken, privs))
            {
                NativeMethods.CloseHandle(hDupToken);
                NativeMethods.CloseHandle(hToken);

                return false;
            }

            if (!ImpersonateThreadToken(hDupToken))
            {
                NativeMethods.CloseHandle(hDupToken);
                NativeMethods.CloseHandle(hToken);

                return false;
            }

            NativeMethods.CloseHandle(hDupToken);
            NativeMethods.CloseHandle(hToken);

            return true;
        }


        public static bool ImpersonateThreadToken(IntPtr hImpersonationToken)
        {
            NTSTATUS ntstatus;
            IntPtr pImpersonationLevel = Marshal.AllocHGlobal(4);
            bool status = NativeMethods.ImpersonateLoggedOnUser(hImpersonationToken);

            if (status)
            {
                SECURITY_IMPERSONATION_LEVEL level;

                ntstatus = NativeMethods.NtQueryInformationToken(
                    WindowsIdentity.GetCurrent().Token,
                    TOKEN_INFORMATION_CLASS.TokenImpersonationLevel,
                    pImpersonationLevel,
                    4u,
                    out uint _);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (status)
                {
                    level = (SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(pImpersonationLevel);

                    if (level == SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation)
                        status = true;
                    else if (level == SECURITY_IMPERSONATION_LEVEL.SecurityDelegation)
                        status = true;
                    else
                        status = false;
                }
            }

            return status;
        }


        public static bool RemoveSinglePrivilege(IntPtr hToken, string privilegeName)
        {
            bool status = NativeMethods.LookupPrivilegeValue(null, privilegeName, out LUID luid);

            if (status)
                status = RemoveSinglePrivilege(hToken, luid);

            return status;
        }


        public static bool RemoveSinglePrivilege(IntPtr hToken, LUID priv)
        {
            int error;
            bool status;
            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES(1);
            tp.Privileges[0].Luid = priv;
            tp.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.REMOVED;
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            status = NativeMethods.AdjustTokenPrivileges(
                hToken,
                false,
                pTokenPrivilege,
                0,
                IntPtr.Zero,
                IntPtr.Zero);
            error = Marshal.GetLastWin32Error();
            status = (status && (error == 0));

            if (!status)
            {
                Console.WriteLine("[-] Failed to remove {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
            }

            return status;
        }

        public static bool SetMandatoryLevel(IntPtr hToken, string mandatoryLevelSid)
        {
            int error;

            if (!NativeMethods.ConvertStringSidToSid(mandatoryLevelSid, out IntPtr pSid))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to resolve integrity level SID.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            var tokenIntegrityLevel = new TOKEN_MANDATORY_LABEL
            {
                Label = new SID_AND_ATTRIBUTES
                {
                    Sid = pSid,
                    Attributes = (uint)(SE_GROUP_ATTRIBUTES.SE_GROUP_INTEGRITY),
                }
            };

            var size = Marshal.SizeOf(tokenIntegrityLevel);
            var pTokenIntegrityLevel = Marshal.AllocHGlobal(size);
            Helpers.ZeroMemory(pTokenIntegrityLevel, size);
            Marshal.StructureToPtr(tokenIntegrityLevel, pTokenIntegrityLevel, true);
            size += NativeMethods.GetLengthSid(pSid);

            Console.WriteLine("[>] Trying to set {0}.",
                Helpers.ConvertStringSidToMandatoryLevelName(mandatoryLevelSid));

            if (!NativeMethods.SetTokenInformation(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                pTokenIntegrityLevel,
                size))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to set integrity level.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                
                return false;
            }

            Console.WriteLine("[+] {0} is set successfully.\n",
                Helpers.ConvertStringSidToMandatoryLevelName(mandatoryLevelSid));

            return true;
        }
    }
}
