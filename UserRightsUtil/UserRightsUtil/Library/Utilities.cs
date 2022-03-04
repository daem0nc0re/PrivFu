using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using UserRightsUtil.Interop;

namespace UserRightsUtil.Library
{
    class Utilities
    {
        public static List<Win32Const.Rights> GetUserRights(IntPtr pSid)
        {
            uint netstatus;
            uint ntstatus;
            IntPtr hLsa;
            var userRight = new Win32Struct.LSA_UNICODE_STRING();
            IntPtr pUserRight;
            var results = new List<Win32Const.Rights>();
            var opt = StringComparison.OrdinalIgnoreCase;
            IntPtr pInfo;
            string accountName;
            string groupName;
            string strSid;
            int resume_handle = 0;

            accountName = Helpers.ConvertSidToAccountName(
                pSid,
                out Win32Const.SID_NAME_USE peUse);

            hLsa = GetSystemLsaHandle(
                Win32Const.PolicyAccessRights.POLICY_LOOKUP_NAMES);

            if (hLsa == IntPtr.Zero)
                return results;

            ntstatus = Win32Api.LsaEnumerateAccountRights(
                hLsa,
                pSid,
                out IntPtr pUserRightsBuffer,
                out ulong count);

            if (ntstatus == Win32Const.STATUS_SUCCESS)
            {
                for (var idx = 0UL; idx < count; idx++)
                {
                    pUserRight = new IntPtr(
                                pUserRightsBuffer.ToInt64() +
                                (long)idx * Marshal.SizeOf(userRight));

                    userRight = (Win32Struct.LSA_UNICODE_STRING)Marshal.PtrToStructure(
                        pUserRight,
                        typeof(Win32Struct.LSA_UNICODE_STRING));

                    results.Add((Win32Const.Rights)Enum.Parse(
                        typeof(Win32Const.Rights),
                        userRight.Buffer));
                }

                Win32Api.LsaFreeMemory(pUserRightsBuffer);
                Win32Api.LsaClose(hLsa);

                return results;
            }
            else
            {
                netstatus = Win32Api.NetUserGetLocalGroups(
                    Environment.MachineName,
                    accountName,
                    0,
                    Win32Const.LG_INCLUDE_INDIRECT,
                    out IntPtr pLocalGroupUserInfo,
                    Win32Const.MAX_PREFERRED_LENGTH,
                    out int entriesread_LG,
                    out int totalentries_LG);

                if (netstatus != Win32Const.NERR_Success)
                    return results;

                netstatus = Win32Api.NetLocalGroupEnum(
                    Environment.MachineName,
                    0,
                    out IntPtr pLocalGroups,
                    Win32Const.MAX_PREFERRED_LENGTH,
                    out int entriesread,
                    out int totalentries,
                    ref resume_handle);

                if (netstatus != Win32Const.NERR_Success)
                    return results;

                try
                {
                    groupName = Marshal.PtrToStringUni(
                        Marshal.ReadIntPtr(pLocalGroupUserInfo));
                }
                catch
                {
                    Win32Api.LsaClose(hLsa);

                    return results;
                }

                for (var num = 0; num < entriesread; num++)
                {
                    pInfo = new IntPtr(
                        pLocalGroups.ToInt64() + num * IntPtr.Size);
                    accountName = Marshal.PtrToStringUni(
                        Marshal.ReadIntPtr(pInfo));

                    if (string.Compare(accountName, groupName, opt) == 0)
                    {
                        strSid = Helpers.ConvertAccountNameToSidString(
                            ref accountName,
                            out peUse);
                        Win32Api.ConvertStringSidToSid(strSid, out pSid);

                        Win32Api.LsaEnumerateAccountRights(
                            hLsa,
                            pSid,
                            out pUserRightsBuffer,
                            out count);

                        for (var idx = 0UL; idx < count; idx++)
                        {
                            pUserRight = new IntPtr(
                                pUserRightsBuffer.ToInt64() +
                                (long)idx * Marshal.SizeOf(userRight));

                            userRight = (Win32Struct.LSA_UNICODE_STRING) Marshal.PtrToStructure(
                                pUserRight,
                                typeof(Win32Struct.LSA_UNICODE_STRING));

                            results.Add((Win32Const.Rights)Enum.Parse(
                                typeof(Win32Const.Rights),
                                userRight.Buffer));
                        }

                        Win32Api.LocalFree(pSid);
                    }
                }

                Win32Api.NetApiBufferFree(pLocalGroups);
                Win32Api.NetApiBufferFree(pLocalGroupUserInfo);
                Win32Api.LsaClose(hLsa);

                return results;
            }
        }


        public static List<string> GetUsersWithRight(
            Win32Const.Rights right)
        {
            int error;
            uint ntstatus;
            IntPtr hLsa;
            IntPtr pEntry;
            IntPtr pSid;
            string accountName;
            var results = new List<string>();
            var policy = Win32Const.PolicyAccessRights.POLICY_LOOKUP_NAMES |
                Win32Const.PolicyAccessRights.POLICY_VIEW_LOCAL_INFORMATION;

            var rights = new Win32Struct.LSA_UNICODE_STRING[1];
            rights[0] = new Win32Struct.LSA_UNICODE_STRING(right.ToString());

            hLsa = GetSystemLsaHandle(policy);

            if (hLsa == IntPtr.Zero)
                return results;

            ntstatus = Win32Api.LsaEnumerateAccountsWithUserRight(
                hLsa,
                rights,
                out IntPtr EnumerationBuffer,
                out int CountReturned);
            Win32Api.LsaClose(hLsa);

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                error = Win32Api.LsaNtStatusToWinError(ntstatus);

                if (error == 0x00000103)
                    return results;

                Console.WriteLine("[-] Failed to enumerate account rights.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Win32Api.LsaClose(hLsa);

                return results;
            }

            for (var idx = 0; idx < CountReturned; idx++)
            {
                pEntry = new IntPtr(EnumerationBuffer.ToInt64() + idx * IntPtr.Size);
                pSid = Marshal.ReadIntPtr(pEntry);

                accountName = Helpers.ConvertSidToAccountName(
                    pSid,
                    out Win32Const.SID_NAME_USE peUse);
                Win32Api.ConvertSidToStringSid(pSid, out string strSid);

                results.Add(string.Format(
                    "{0} (SID : {1}, Type : {2})",
                    accountName,
                    strSid,
                    peUse.ToString()));
            }

            Win32Api.LsaFreeMemory(EnumerationBuffer);

            return results;
        }


        public static IntPtr GetSystemLsaHandle(
            Win32Const.PolicyAccessRights policyAccess)
        {
            int error;
            uint ntstatus;
            var lsaObjAttrs = new Win32Struct.LSA_OBJECT_ATTRIBUTES();
            lsaObjAttrs.Length = Marshal.SizeOf(lsaObjAttrs);

            ntstatus = Win32Api.LsaOpenPolicy(
                IntPtr.Zero,
                ref lsaObjAttrs,
                policyAccess,
                out IntPtr lsaHandle);

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                error = Win32Api.LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to get LSA handle.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            return lsaHandle;
        }

        public static bool GrantSingleUserRight(
            IntPtr hLsa,
            string strSid,
            Win32Const.Rights right)
        {
            int error;
            uint ntstatus;

            if (!Win32Api.ConvertStringSidToSid(strSid, out IntPtr pSid))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to resolve SID ({0}).", strSid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            var privs = new Win32Struct.LSA_UNICODE_STRING[1];
            privs[0] = new Win32Struct.LSA_UNICODE_STRING(right.ToString());

            Console.WriteLine("[>] Trying to grant {0}.", right.ToString());

            ntstatus = Win32Api.LsaAddAccountRights(hLsa, pSid, privs, 1);

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                error = Win32Api.LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to grant right.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, true));

                return false;
            }

            Console.WriteLine("[+] {0} is granted successfully.", right.ToString());

            return true;
        }


        public static bool RevokeSingleUserRight(
            IntPtr hLsa,
            string strSid,
            Win32Const.Rights right)
        {
            int error;
            uint ntstatus;

            if (!Win32Api.ConvertStringSidToSid(strSid, out IntPtr pSid))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to resolve SID ({0}).", strSid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            var privs = new Win32Struct.LSA_UNICODE_STRING[1];
            privs[0] = new Win32Struct.LSA_UNICODE_STRING(right.ToString());

            Console.WriteLine("[>] Trying to revoke {0}", right.ToString());

            ntstatus = Win32Api.LsaRemoveAccountRights(hLsa, pSid, false, privs, 1);

            if (ntstatus != Win32Const.STATUS_SUCCESS)
            {
                error = Win32Api.LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to revoke right.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, true));

                return false;
            }

            Console.WriteLine("[+] {0} is revoked successfully.", right.ToString());

            return true;
        }
    }
}
