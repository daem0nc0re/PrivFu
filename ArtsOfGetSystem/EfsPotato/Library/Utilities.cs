using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using EfsPotato.Interop;

namespace EfsPotato.Library
{
    internal class Utilities
    {
        public static IntPtr CreateNewNamedPipe(string pipePath)
        {
            var hPipe = Win32Consts.INVALID_HANDLE_VALUE;

            do
            {
                var securityAttributes = new SECURITY_ATTRIBUTES
                {
                    nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES))
                };
                var status = NativeMethods.ConvertStringSecurityDescriptorToSecurityDescriptor(
                    "D:(A;OICI;GA;;;WD)",
                    Win32Consts.SDDL_REVISION_1,
                    out securityAttributes.lpSecurityDescriptor,
                    out uint _);

                if (!status)
                    break;

                hPipe = NativeMethods.CreateNamedPipe(
                    pipePath,
                    PIPE_OPEN_MODE.PIPE_ACCESS_DUPLEX | PIPE_OPEN_MODE.FILE_FLAG_OVERLAPPED,
                    PIPE_TYPE.BYTE | PIPE_TYPE.WAIT,
                    0x10,
                    1024,
                    1024,
                    0,
                    in securityAttributes);
                NativeMethods.LocalFree(securityAttributes.lpSecurityDescriptor);
            } while (false);

            return hPipe;
        }


        public static bool EnableTokenPrivileges(
            List<string> requiredPrivs,
            out Dictionary<string, bool> adjustedPrivs)
        {
            return EnableTokenPrivileges(
                WindowsIdentity.GetCurrent().Token,
                requiredPrivs,
                out adjustedPrivs);
        }


        public static bool EnableTokenPrivileges(
            IntPtr hToken,
            List<string> requiredPrivs,
            out Dictionary<string, bool> adjustedPrivs)
        {
            var allEnabled = true;
            adjustedPrivs = new Dictionary<string, bool>();

            do
            {
                if (requiredPrivs.Count == 0)
                    break;

                allEnabled = Helpers.GetTokenPrivileges(
                    hToken,
                    out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                if (!allEnabled)
                    break;

                foreach (var priv in requiredPrivs)
                {
                    adjustedPrivs.Add(priv, false);

                    foreach (var available in availablePrivs)
                    {
                        if (Helpers.CompareIgnoreCase(available.Key, priv))
                        {
                            if ((available.Value & SE_PRIVILEGE_ATTRIBUTES.Enabled) != 0)
                            {
                                adjustedPrivs[priv] = true;
                            }
                            else
                            {
                                IntPtr pTokenPrivileges = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));
                                var tokenPrivileges = new TOKEN_PRIVILEGES
                                {
                                    PrivilegeCount = 1,
                                    Privileges = new LUID_AND_ATTRIBUTES[1]
                                };

                                if (NativeMethods.LookupPrivilegeValue(
                                    null,
                                    priv,
                                    out tokenPrivileges.Privileges[0].Luid))
                                {
                                    tokenPrivileges.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.Enabled;
                                    Marshal.StructureToPtr(tokenPrivileges, pTokenPrivileges, true);

                                    adjustedPrivs[priv] = NativeMethods.AdjustTokenPrivileges(
                                        hToken,
                                        false,
                                        pTokenPrivileges,
                                        Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)),
                                        IntPtr.Zero,
                                        out int _);
                                    adjustedPrivs[priv] = (adjustedPrivs[priv] && (Marshal.GetLastWin32Error() == 0));
                                }

                                Marshal.FreeHGlobal(pTokenPrivileges);
                            }

                            break;
                        }
                    }

                    if (!adjustedPrivs[priv])
                        allEnabled = false;
                }
            } while (false);

            return allEnabled;
        }
    }
}
