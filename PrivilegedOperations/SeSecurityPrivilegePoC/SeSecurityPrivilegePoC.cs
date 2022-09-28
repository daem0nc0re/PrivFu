using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;

namespace SeSecurityPrivilegePoC
{
    class SeSecurityPrivilegePoC
    {
        /*
         * P/Invoke : Enums
         */
        [Flags]
        enum EVENT_TYPES : short
        {
            EVENTLOG_ERROR_TYPE = 0x0001,
            EVENTLOG_WARNING_TYPE = 0x0002,
            EVENTLOG_INFORMATION_TYPE = 0x0004,
            EVENTLOG_AUDIT_SUCCESS = 0x0008,
            EVENTLOG_AUDIT_FAILURE = 0x0010
        }

        [Flags]
        enum EventReadFlags : uint
        {
            EVENTLOG_SEQUENTIAL_READ = 0x00000001,
            EVENTLOG_SEEK_READ = 0x00000002,
            EVENTLOG_FORWARDS_READ = 0x00000004,
            EVENTLOG_BACKWARDS_READ = 0x00000008
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
         * P/Invoke : Structs
         */
        [StructLayout(LayoutKind.Sequential)]
        struct EVENTLOGRECORD
        {
            public int Length;
            public int Reserved;
            public int RecordNumber;
            public int TimeGenerated;
            public int TimeWritten;
            public int EventID;
            public short EventType;
            public short NumStrings;
            public short EventCategory;
            public short ReservedFlags;
            public int ClosingRecordNumber;
            public int StringOffset;
            public int UserSidLength;
            public int UserSidOffset;
            public int DataLength;
            public int DataOffset;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct FILETIME
        {
            public uint DateTimeLow;
            public uint DateTimeHigh;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SYSTEMTIME
        {
            public short Year;
            public short Month;
            public short DayOfWeek;
            public short Day;
            public short Hour;
            public short Minute;
            public short Second;
            public short Milliseconds;

            public SYSTEMTIME(DateTime dt)
            {
                dt = dt.ToUniversalTime();
                Year = (short)dt.Year;
                Month = (short)dt.Month;
                DayOfWeek = (short)dt.DayOfWeek;
                Day = (short)dt.Day;
                Hour = (short)dt.Hour;
                Minute = (short)dt.Minute;
                Second = (short)dt.Second;
                Milliseconds = (short)dt.Millisecond;
            }
        }

        /*
         * P/Invoke : Win32 APIs
         */
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CloseEventLog(IntPtr hEventLog);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertStringSidToSid(string StringSid, out IntPtr pSid);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FileTimeToSystemTime(
            ref FILETIME lpFileTime,
            out SYSTEMTIME lpSystemTime);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern int FormatMessage(
            FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool LookupAccountName(
            string lpSystemName,
            string lpAccountName,
            IntPtr Sid,
            ref int cbSid,
            StringBuilder ReferencedDomainName,
            ref int cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool LookupAccountSid(
            string strSystemName,
            IntPtr pSid,
            StringBuilder pName,
            ref int cchName,
            StringBuilder pReferencedDomainName,
            ref int cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenEventLog(
            string lpUNCServerName,
            string lpSourceName);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool ReadEventLog(
            IntPtr hEventLog,
            EventReadFlags dwReadFlags,
            int dwRecordOffset,
            IntPtr lpBuffer,
            int nNumberOfBytesToRead,
            out int pnBytesRead,
            out int pnMinNumberOfBytesNeeded);

        /*
         * Windows Consts
         */
        const int ERROR_INSUFFICIENT_BUFFER = 122;

        /*
         * User defined functions
         */
        static string ConvertSidStringToAccountName(
            ref string sid,
            out SID_NAME_USE peUse)
        {
            string accountName;
            sid = sid.ToUpper();

            if (!ConvertStringSidToSid(sid, out IntPtr pSid))
            {
                peUse = 0;
                return null;
            }

            accountName = ConvertSidToAccountName(pSid, out peUse);
            LocalFree(pSid);

            return accountName;
        }


        static string ConvertSidToAccountName(
            IntPtr pSid,
            out SID_NAME_USE peUse)
        {
            bool status;
            int error;
            StringBuilder pName = new StringBuilder();
            int cchName = 4;
            StringBuilder pReferencedDomainName = new StringBuilder();
            int cchReferencedDomainName = 4;

            do
            {
                pName.Capacity = cchName;
                pReferencedDomainName.Capacity = cchReferencedDomainName;

                status = LookupAccountSid(
                    null,
                    pSid,
                    pName,
                    ref cchName,
                    pReferencedDomainName,
                    ref cchReferencedDomainName,
                    out peUse);
                error = Marshal.GetLastWin32Error();

                if (!status)
                {
                    pName.Clear();
                    pReferencedDomainName.Clear();
                }
            } while (!status && error == ERROR_INSUFFICIENT_BUFFER);

            if (!status)
                return null;

            if (peUse == SID_NAME_USE.SidTypeDomain)
            {
                return pReferencedDomainName.ToString();
            }
            else if (cchName == 0)
            {
                return pReferencedDomainName.ToString();
            }
            else if (cchReferencedDomainName == 0)
            {
                return pName.ToString();
            }
            else
            {
                return string.Format("{0}\\{1}",
                    pReferencedDomainName.ToString(),
                    pName.ToString());
            }
        }


        static string FormatTime(SYSTEMTIME systemTime)
        {
            return string.Format(
                "{0}/{1}/{2} {3}:{4}:{5}.{6}",
                systemTime.Year,
                systemTime.Month,
                systemTime.Day,
                systemTime.Hour,
                systemTime.Minute,
                systemTime.Second,
                systemTime.Milliseconds);
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


        static void PrintEventRecord(IntPtr buffer)
        {
            var record = (EVENTLOGRECORD)Marshal.PtrToStructure(
                buffer,
                typeof(EVENTLOGRECORD));
            short numStrings = record.NumStrings;
            IntPtr pUserSidString = new IntPtr(buffer.ToInt64() + record.UserSidOffset);
            IntPtr pStrings = new IntPtr(buffer.ToInt64() + record.StringOffset);
            IntPtr pData = new IntPtr(buffer.ToInt64() + record.DataOffset);
            string userSidString = Marshal.PtrToStringUni(pUserSidString);
            IntPtr pUnicodeText = pStrings;
            string unicodeText;

            string accountName = ConvertSidStringToAccountName(
                ref userSidString,
                out SID_NAME_USE peUse);

            Console.WriteLine("Event ID       : {0}", record.EventID);
            Console.WriteLine("Event Type     : {0}", (EVENT_TYPES)record.EventType);
            Console.WriteLine("Event Category : {0}", record.EventCategory);

            if (string.IsNullOrEmpty(accountName))
            {
                Console.WriteLine("Security ID    : {0}", userSidString);
            }
            else
            {
                Console.WriteLine(
                    "Security ID    : {0} (Account : {1}, Type : {2})",
                    userSidString,
                    accountName,
                    peUse);
            }

            TimeToSystemTime((long)record.TimeGenerated, out SYSTEMTIME generatedTime);
            TimeToSystemTime((long)record.TimeWritten, out SYSTEMTIME writtenTime);

            Console.WriteLine("Generated Time : {0}", FormatTime(generatedTime));
            Console.WriteLine("Written Time   : {0}", FormatTime(writtenTime));

            if (numStrings > 0)
                Console.WriteLine("String Data    :");

            for (short count = 0; count < numStrings; count++)
            {
                unicodeText = Marshal.PtrToStringUni(pUnicodeText);
                Console.WriteLine("\tEntries[{0}]:", count);
                Console.WriteLine("\t\t{0}", Regex.Replace(unicodeText, @"\t+", "\t\t"));
                pUnicodeText = new IntPtr(pUnicodeText.ToInt64() + (unicodeText.Length * 2) + 2);
            }

            if (record.DataLength > 0)
            {
                Console.WriteLine("Data:\n");
                HexDump.Dump(pData, record.DataLength, 1);
            }
        }


        static bool ReadSecurityEvents()
        {
            int error;
            bool status;
            IntPtr buffer;
            int nNumberOfBytesToRead = 0x8;

            Console.WriteLine("[>] Trying to open security event logs.");
            IntPtr hEventLog = OpenEventLog(null, "Security");

            if (hEventLog == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open security event log.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }

            Console.WriteLine("[+] Got handle to security event logs.");
            Console.WriteLine("    |-> hEventLog = 0x{0}", hEventLog.ToString("X"));

            do
            {
                buffer = Marshal.AllocHGlobal(nNumberOfBytesToRead);
                status = ReadEventLog(
                    hEventLog,
                    EventReadFlags.EVENTLOG_SEQUENTIAL_READ | EventReadFlags.EVENTLOG_BACKWARDS_READ,
                    0,
                    buffer,
                    nNumberOfBytesToRead,
                    out int pnBytesRead,
                    out int pnMinNumberOfBytesNeeded);
                error = Marshal.GetLastWin32Error();

                if (!status)
                {
                    Marshal.FreeHGlobal(buffer);
                    nNumberOfBytesToRead = pnMinNumberOfBytesNeeded;
                }
                else
                {
                    Console.WriteLine("[+] A security event log read successfully.");
                    Console.WriteLine("[*] Event Log Size = {0} bytes", pnBytesRead);
                }
            } while (!status && error == ERROR_INSUFFICIENT_BUFFER);

            if (hEventLog != IntPtr.Zero)
                CloseEventLog(hEventLog);

            if (!status)
            {
                Console.WriteLine("[-] Failed to read security event logs.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }

            Console.WriteLine("[*] Event Data:\n");
            PrintEventRecord(buffer);
            Marshal.FreeHGlobal(buffer);

            return true;
        }


        static bool TimeToSystemTime(long time, out SYSTEMTIME systemTime)
        {
            time = (time * 10000000L) + 116444736000000000L;
            var fileTime = new FILETIME
            {
                DateTimeLow = (uint)(time & 0xFFFFFFFFL),
                DateTimeHigh = (uint)((time >> 32) & 0xFFFFFFFFL)
            };

            return FileTimeToSystemTime(
                ref fileTime,
                out systemTime);
        }


        static void Main(string[] args)
        {
            Console.WriteLine("[*] If you have SeSecurityPrivilege, you can read security events.");
            Console.WriteLine("[*] This PoC tries to read the latest security event.");
            ReadSecurityEvents();
        }
    }
}
