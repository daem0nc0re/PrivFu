using PrivMan.Interop;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PrivMan.Library
{
    internal class Modules
    {
        internal static bool DisablePrivileges(int pid, string namePattern)
        {
            string processName;
            var bSuccess = false;
            List<string> names = TokenPrivileges.GetPrivilegeNames(namePattern);

            try
            {
                processName = Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                Console.WriteLine("[-] Failed to find the specified process (PID: {0}).", pid);
                return false;
            }

            try
            {
                using (var ops = new DeviceOperations())
                {
                    var bitMask = 0UL;
                    var input = new IOCTL_SET_TOKEN_PRIVILEGES_INPUT
                    {
                        UniqueProcess = new IntPtr(pid)
                    };

                    Console.WriteLine("[*] Trying to disable the following privileges for '{0}' (PID: {1}).\n",
                        processName,
                        pid);
                    Console.WriteLine(TokenPrivileges.GetPrivilegeLuidTable(in names));
                    bSuccess = ops.GetTokenPrivileges(pid, out IOCTL_GET_TOKEN_PRIVILEGES_OUTPUT info);

                    if (!bSuccess)
                    {
                        throw new Exception(string.Format("Failed to get current SEP_TOKEN_PRIVILEGES (Error = {0}).",
                            Marshal.GetLastWin32Error()));
                    }

                    foreach (var name in names)
                        bitMask |= TokenPrivileges.BitMasks[name];

                    input.Privileges.Present = info.Privileges.Present;
                    input.Privileges.Enabled = info.Privileges.Enabled & ~bitMask;
                    input.Privileges.EnabledByDefault = info.Privileges.EnabledByDefault;

                    Console.WriteLine("[*] Trying to overwrite SEP_TOKEN_PRIVILEGES:");
                    Console.WriteLine("    [*] Present          : {0}",
                        input.Privileges.Present.ToString("X16"));
                    Console.WriteLine("    [*] Enabled          : {0}",
                        input.Privileges.Enabled.ToString("X16"));
                    Console.WriteLine("    [*] EnabledByDefault : {0}",
                        input.Privileges.EnabledByDefault.ToString("X16"));

                    bSuccess = ops.SetTokenPrivileges(in input);

                    if (!bSuccess)
                    {
                        throw new Exception(string.Format("Failed to overwrite SEP_TOKEN_PRIVILEGES (Error = {0}).",
                            Marshal.GetLastWin32Error()));
                    }
                    else
                    {
                        Console.WriteLine("[+] Token privileges are disabled successfully.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] {0}", ex.Message);
            }

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        internal static bool EnablePrivileges(int pid, string namePattern)
        {
            string processName;
            var bSuccess = false;
            List<string> names = TokenPrivileges.GetPrivilegeNames(namePattern);

            try
            {
                processName = Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                Console.WriteLine("[-] Failed to find the specified process (PID: {0}).", pid);
                return false;
            }

            try
            {
                using (var ops = new DeviceOperations())
                {
                    var bitMask = 0UL;
                    var input = new IOCTL_SET_TOKEN_PRIVILEGES_INPUT
                    {
                        UniqueProcess = new IntPtr(pid)
                    };

                    Console.WriteLine("[*] Trying to enable the following privileges for '{0}' (PID: {1}).\n",
                        processName,
                        pid);
                    Console.WriteLine(TokenPrivileges.GetPrivilegeLuidTable(in names));
                    bSuccess = ops.GetTokenPrivileges(pid, out IOCTL_GET_TOKEN_PRIVILEGES_OUTPUT info);

                    if (!bSuccess)
                    {
                        throw new Exception(string.Format("Failed to get current SEP_TOKEN_PRIVILEGES (Error = {0}).",
                            Marshal.GetLastWin32Error()));
                    }

                    foreach (var name in names)
                        bitMask |= TokenPrivileges.BitMasks[name];

                    input.Privileges.Present = info.Privileges.Present | bitMask;
                    input.Privileges.Enabled = info.Privileges.Enabled | bitMask;
                    input.Privileges.EnabledByDefault = info.Privileges.EnabledByDefault;

                    Console.WriteLine("[*] Trying to overwrite SEP_TOKEN_PRIVILEGES:");
                    Console.WriteLine("    [*] Present          : {0}",
                        input.Privileges.Present.ToString("X16"));
                    Console.WriteLine("    [*] Enabled          : {0}",
                        input.Privileges.Enabled.ToString("X16"));
                    Console.WriteLine("    [*] EnabledByDefault : {0}",
                        input.Privileges.EnabledByDefault.ToString("X16"));

                    bSuccess = ops.SetTokenPrivileges(in input);

                    if (!bSuccess)
                    {
                        throw new Exception(string.Format("Failed to overwrite SEP_TOKEN_PRIVILEGES (Error = {0}).",
                            Marshal.GetLastWin32Error()));
                    }
                    else
                    {
                        Console.WriteLine("[+] Token privileges are enabled successfully.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] {0}", ex.Message);
            }

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        internal static bool FilterPrivileges(int pid, string namePattern)
        {
            string processName;
            var bSuccess = false;
            List<string> names = TokenPrivileges.GetPrivilegeNames(namePattern);

            try
            {
                processName = Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                Console.WriteLine("[-] Failed to find the specified process (PID: {0}).", pid);
                return false;
            }

            try
            {
                using (var ops = new DeviceOperations())
                {
                    var bitMask = 0UL;
                    var input = new IOCTL_SET_TOKEN_PRIVILEGES_INPUT
                    {
                        UniqueProcess = new IntPtr(pid)
                    };

                    Console.WriteLine("[*] Trying to filter the following privileges for '{0}' (PID: {1}).\n",
                        processName,
                        pid);
                    Console.WriteLine(TokenPrivileges.GetPrivilegeLuidTable(in names));
                    bSuccess = ops.GetTokenPrivileges(pid, out IOCTL_GET_TOKEN_PRIVILEGES_OUTPUT info);

                    if (!bSuccess)
                    {
                        throw new Exception(string.Format("Failed to get current SEP_TOKEN_PRIVILEGES (Error = {0}).",
                            Marshal.GetLastWin32Error()));
                    }

                    foreach (var name in names)
                        bitMask |= TokenPrivileges.BitMasks[name];

                    input.Privileges.Present = info.Privileges.Present & bitMask;
                    input.Privileges.Enabled = info.Privileges.Enabled & bitMask;
                    input.Privileges.EnabledByDefault = info.Privileges.EnabledByDefault & bitMask;

                    Console.WriteLine("[*] Trying to overwrite SEP_TOKEN_PRIVILEGES:");
                    Console.WriteLine("    [*] Present          : {0}",
                        input.Privileges.Present.ToString("X16"));
                    Console.WriteLine("    [*] Enabled          : {0}",
                        input.Privileges.Enabled.ToString("X16"));
                    Console.WriteLine("    [*] EnabledByDefault : {0}",
                        input.Privileges.EnabledByDefault.ToString("X16"));

                    bSuccess = ops.SetTokenPrivileges(in input);

                    if (!bSuccess)
                    {
                        throw new Exception(string.Format("Failed to overwrite SEP_TOKEN_PRIVILEGES (Error = {0}).",
                            Marshal.GetLastWin32Error()));
                    }
                    else
                    {
                        Console.WriteLine("[+] Token privileges are filtered successfully.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] {0}", ex.Message);
            }

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        internal static bool GetCurrentPrivileges(int pid)
        {
            string processName;
            var bSuccess = false;

            try
            {
                processName = Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                Console.WriteLine("[-] Failed to find the specified process (PID: {0}).", pid);
                return false;
            }

            try
            {
                using (var ops = new DeviceOperations())
                {
                    Console.WriteLine("[*] Trying to get current token privielges status for '{0}' (PID: {1}).\n",
                        processName,
                        pid);
                    bSuccess = ops.GetTokenPrivileges(pid, out IOCTL_GET_TOKEN_PRIVILEGES_OUTPUT info);

                    if (!bSuccess)
                    {
                        throw new Exception(string.Format("Failed to get current SEP_TOKEN_PRIVILEGES (Error = {0}).",
                            Marshal.GetLastWin32Error()));
                    }

                    Console.WriteLine(TokenPrivileges.GetPrivilegeStateTable(in info.Privileges));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] {0}", ex.Message);
            }

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        internal static bool RemovePrivileges(int pid, string namePattern)
        {
            string processName;
            var bSuccess = false;
            List<string> names = TokenPrivileges.GetPrivilegeNames(namePattern);

            try
            {
                processName = Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                Console.WriteLine("[-] Failed to find the specified process (PID: {0}).", pid);
                return false;
            }

            try
            {
                using (var ops = new DeviceOperations())
                {
                    var bitMask = 0UL;
                    var input = new IOCTL_SET_TOKEN_PRIVILEGES_INPUT
                    {
                        UniqueProcess = new IntPtr(pid)
                    };

                    Console.WriteLine("[*] Trying to remove the following privileges for '{0}' (PID: {1}).\n",
                        processName,
                        pid);
                    Console.WriteLine(TokenPrivileges.GetPrivilegeLuidTable(in names));
                    bSuccess = ops.GetTokenPrivileges(pid, out IOCTL_GET_TOKEN_PRIVILEGES_OUTPUT info);

                    if (!bSuccess)
                    {
                        throw new Exception(string.Format("Failed to get current SEP_TOKEN_PRIVILEGES (Error = {0}).",
                            Marshal.GetLastWin32Error()));
                    }

                    foreach (var name in names)
                        bitMask |= TokenPrivileges.BitMasks[name];

                    input.Privileges.Present = info.Privileges.Present & ~bitMask;
                    input.Privileges.Enabled = info.Privileges.Enabled & ~bitMask;
                    input.Privileges.EnabledByDefault = info.Privileges.EnabledByDefault & ~bitMask;

                    Console.WriteLine("[*] Trying to overwrite SEP_TOKEN_PRIVILEGES:");
                    Console.WriteLine("    [*] Present          : {0}",
                        input.Privileges.Present.ToString("X16"));
                    Console.WriteLine("    [*] Enabled          : {0}",
                        input.Privileges.Enabled.ToString("X16"));
                    Console.WriteLine("    [*] EnabledByDefault : {0}",
                        input.Privileges.EnabledByDefault.ToString("X16"));

                    bSuccess = ops.SetTokenPrivileges(in input);

                    if (!bSuccess)
                    {
                        throw new Exception(string.Format("Failed to overwrite SEP_TOKEN_PRIVILEGES (Error = {0}).",
                            Marshal.GetLastWin32Error()));
                    }
                    else
                    {
                        Console.WriteLine("[+] Token privileges are removed successfully.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] {0}", ex.Message);
            }

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }
    }
}
