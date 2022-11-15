using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using SwitchPriv.Interop;

namespace SwitchPriv.Library
{
    internal class Utilities
    {
        public static bool DisableSinglePrivilege(
            IntPtr hToken,
            LUID priv)
        {
            int error;

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES(1);
            tp.Privileges[0].Luid = priv;
            tp.Privileges[0].Attributes = 0;

            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(tp));
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            if (!NativeMethods.AdjustTokenPrivileges(
                hToken,
                false,
                pTokenPrivilege,
                0,
                IntPtr.Zero,
                IntPtr.Zero))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to disable {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            error = Marshal.GetLastWin32Error();

            if (error != 0)
            {
                Console.WriteLine("[-] Failed to disable {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                
                return false;
            }

            return true;
        }


        public static bool EnableMultiplePrivileges(
            IntPtr hToken,
            string[] privs)
        {
            StringComparison opt = StringComparison.OrdinalIgnoreCase;
            Dictionary<string, bool> results = new Dictionary<string, bool>();
            var privList = new List<string>(privs);
            var availablePrivs = GetAvailablePrivileges(hToken);
            bool isEnabled;
            bool enabledAll = true;

            foreach (var name in privList)
            {
                results.Add(name, false);
            }

            foreach (var priv in availablePrivs)
            {
                foreach (var name in privList)
                {
                    if (string.Compare(Helpers.GetPrivilegeName(priv.Key), name, opt) == 0)
                    {
                        isEnabled = ((priv.Value & (uint)SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED) != 0);

                        if (isEnabled)
                        {
                            results[name] = true;
                        }
                        else
                        {
                            results[name] = EnableSinglePrivilege(hToken, priv.Key);
                        }
                    }
                }
            }

            foreach (var result in results)
            {
                if (!result.Value)
                {
                    Console.WriteLine(
                        "[-] {0} is not available.",
                        result.Key);

                    enabledAll = false;
                }
            }

            return enabledAll;
        }


        public static bool EnableSinglePrivilege(
            IntPtr hToken,
            LUID priv)
        {
            int error;

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES(1);
            tp.Privileges[0].Luid = priv;
            tp.Privileges[0].Attributes = (uint)PrivilegeAttributeFlags.SE_PRIVILEGE_ENABLED;

            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(tp));
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            if (!NativeMethods.AdjustTokenPrivileges(
                hToken,
                false,
                pTokenPrivilege,
                0,
                IntPtr.Zero,
                IntPtr.Zero))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to enable {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            error = Marshal.GetLastWin32Error();

            if (error != 0)
            {
                Console.WriteLine("[-] Failed to enable {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                
                return false;
            }

            return true;
        }


        public static Dictionary<LUID, uint> GetAvailablePrivileges(IntPtr hToken)
        {
            int ERROR_INSUFFICIENT_BUFFER = 122;
            int error;
            bool status;
            int bufferLength = Marshal.SizeOf(typeof(TOKEN_PRIVILEGES));
            Dictionary<LUID, uint> availablePrivs = new Dictionary<LUID, uint>();
            IntPtr pTokenPrivileges;

            do
            {
                pTokenPrivileges = Marshal.AllocHGlobal(bufferLength);
                Helpers.ZeroMemory(pTokenPrivileges, bufferLength);

                status = NativeMethods.GetTokenInformation(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenPrivileges,
                    pTokenPrivileges,
                    bufferLength,
                    out bufferLength);
                error = Marshal.GetLastWin32Error();

                if (!status)
                    Marshal.FreeHGlobal(pTokenPrivileges);
            } while (!status && (error == ERROR_INSUFFICIENT_BUFFER));

            if (!status)
                return availablePrivs;

            int privCount = Marshal.ReadInt32(pTokenPrivileges);
            IntPtr buffer = new IntPtr(pTokenPrivileges.ToInt64() + Marshal.SizeOf(privCount));

            for (var count = 0; count < privCount; count++)
            {
                var luidAndAttr = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                    buffer,
                    typeof(LUID_AND_ATTRIBUTES));

                availablePrivs.Add(luidAndAttr.Luid, luidAndAttr.Attributes);
                buffer = new IntPtr(buffer.ToInt64() + Marshal.SizeOf(luidAndAttr));
            }

            Marshal.FreeHGlobal(pTokenPrivileges);

            return availablePrivs;
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
            int error;

            Console.WriteLine("[>] Trying to impersonate thread token.");
            Console.WriteLine("    |-> Current Thread ID : {0}", NativeMethods.GetCurrentThreadId());

            if (!NativeMethods.ImpersonateLoggedOnUser(hImpersonationToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to impersonation.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            IntPtr hCurrentToken = WindowsIdentity.GetCurrent().Token;
            IntPtr pImpersonationLevel = Helpers.GetInformationFromToken(
                hCurrentToken,
                TOKEN_INFORMATION_CLASS.TokenImpersonationLevel);
            var impersonationLevel = (SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(
                pImpersonationLevel);
            NativeMethods.LocalFree(pImpersonationLevel);

            if (impersonationLevel ==
                SECURITY_IMPERSONATION_LEVEL.SecurityIdentification)
            {
                Console.WriteLine("[-] Failed to impersonation.");
                Console.WriteLine("    |-> May not have {0}.\n", Win32Consts.SE_IMPERSONATE_NAME);

                return false;
            }
            else
            {
                Console.WriteLine("[+] Impersonation is successful.");

                return true;
            }
        }


        public static bool RemoveSinglePrivilege(IntPtr hToken, LUID priv)
        {
            int error;

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES(1);
            tp.Privileges[0].Luid = priv;
            tp.Privileges[0].Attributes = (uint)SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_REMOVED;

            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(tp));
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            if (!NativeMethods.AdjustTokenPrivileges(
                hToken,
                false,
                pTokenPrivilege,
                0,
                IntPtr.Zero,
                IntPtr.Zero))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to remove {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            error = Marshal.GetLastWin32Error();

            if (error != 0)
            {
                Console.WriteLine("[-] Failed to remove {0}.", Helpers.GetPrivilegeName(priv));
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            return true;
        }

        public static bool SetMandatoryLevel(
            IntPtr hToken,
            string mandatoryLevelSid)
        {
            int error;

            if (!NativeMethods.ConvertStringSidToSid(
                mandatoryLevelSid,
                out IntPtr pSid))
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
