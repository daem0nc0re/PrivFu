using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using UserRightsUtil.Interop;

namespace UserRightsUtil.Library
{
    internal class Utilities
    {
        public static List<Rights> GetUserRights(IntPtr pSid)
        {
            int ntstatus;
            IntPtr hLsa;
            var userRight = new LSA_UNICODE_STRING();
            IntPtr pUserRight;
            Rights right;
            var results = new List<Rights>();
            var opt = StringComparison.OrdinalIgnoreCase;
            IntPtr pInfo;
            string accountName;
            string groupName;
            string strSid;
            int resume_handle = 0;

            accountName = Helpers.ConvertSidToAccountName(
                pSid,
                out SID_NAME_USE peUse);

            hLsa = GetSystemLsaHandle(
                PolicyAccessRights.POLICY_LOOKUP_NAMES);

            if (hLsa == IntPtr.Zero)
                return results;

            ntstatus = NativeMethods.LsaEnumerateAccountRights(
                hLsa,
                pSid,
                out IntPtr pUserRightsBuffer,
                out ulong count);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                for (var idx = 0UL; idx < count; idx++)
                {
                    pUserRight = new IntPtr(
                                pUserRightsBuffer.ToInt64() +
                                (long)idx * Marshal.SizeOf(userRight));

                    userRight = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                        pUserRight,
                        typeof(LSA_UNICODE_STRING));

                    right = (Rights)Enum.Parse(
                        typeof(Rights),
                        userRight.Buffer);

                    if (!results.Contains(right))
                        results.Add(right);
                }
            }

            if (peUse != SID_NAME_USE.SidTypeAlias)
            {
                ntstatus = NativeMethods.NetUserGetLocalGroups(
                    Environment.MachineName,
                    accountName,
                    0,
                    Win32Consts.LG_INCLUDE_INDIRECT,
                    out IntPtr pLocalGroupUserInfo,
                    Win32Consts.MAX_PREFERRED_LENGTH,
                    out int entriesread_LG,
                    out int totalentries_LG);

                if (ntstatus != Win32Consts.NERR_Success)
                {
                    NativeMethods.LsaClose(hLsa);

                    return results;
                }

                ntstatus = NativeMethods.NetLocalGroupEnum(
                    Environment.MachineName,
                    0,
                    out IntPtr pLocalGroups,
                    Win32Consts.MAX_PREFERRED_LENGTH,
                    out int entriesread,
                    out int totalentries,
                    ref resume_handle);

                if (ntstatus != Win32Consts.NERR_Success)
                {
                    NativeMethods.LsaClose(hLsa);

                    return results;
                }

                try
                {
                    groupName = Marshal.PtrToStringUni(
                        Marshal.ReadIntPtr(pLocalGroupUserInfo));
                }
                catch
                {
                    NativeMethods.LsaClose(hLsa);

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
                        NativeMethods.ConvertStringSidToSid(strSid, out pSid);

                        NativeMethods.LsaEnumerateAccountRights(
                            hLsa,
                            pSid,
                            out pUserRightsBuffer,
                            out count);

                        for (var idx = 0UL; idx < count; idx++)
                        {
                            pUserRight = new IntPtr(
                                pUserRightsBuffer.ToInt64() +
                                (long)idx * Marshal.SizeOf(userRight));

                            userRight = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                                pUserRight,
                                typeof(LSA_UNICODE_STRING));

                            right = (Rights)Enum.Parse(
                                typeof(Rights),
                                userRight.Buffer);

                            if (!results.Contains(right))
                                results.Add(right);
                        }

                        NativeMethods.LocalFree(pSid);
                    }
                }

                NativeMethods.NetApiBufferFree(pLocalGroups);
                NativeMethods.NetApiBufferFree(pLocalGroupUserInfo);
            }

            NativeMethods.LsaClose(hLsa);

            return results;
        }


        public static List<string> GetUsersWithRight(
            Rights right)
        {
            int error;
            int ntstatus;
            IntPtr hLsa;
            IntPtr pEntry;
            IntPtr pSid;
            string accountName;
            var results = new List<string>();
            var policy = PolicyAccessRights.POLICY_LOOKUP_NAMES |
                PolicyAccessRights.POLICY_VIEW_LOCAL_INFORMATION;

            var rights = new LSA_UNICODE_STRING[1];
            rights[0] = new LSA_UNICODE_STRING(right.ToString());

            hLsa = GetSystemLsaHandle(policy);

            if (hLsa == IntPtr.Zero)
                return results;

            ntstatus = NativeMethods.LsaEnumerateAccountsWithUserRight(
                hLsa,
                rights,
                out IntPtr EnumerationBuffer,
                out int CountReturned);
            NativeMethods.LsaClose(hLsa);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                error = NativeMethods.LsaNtStatusToWinError(ntstatus);

                if (error == 0x00000103)
                    return results;

                Console.WriteLine("[-] Failed to enumerate account rights.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                NativeMethods.LsaClose(hLsa);

                return results;
            }

            for (var idx = 0; idx < CountReturned; idx++)
            {
                pEntry = new IntPtr(EnumerationBuffer.ToInt64() + idx * IntPtr.Size);
                pSid = Marshal.ReadIntPtr(pEntry);

                accountName = Helpers.ConvertSidToAccountName(
                    pSid,
                    out SID_NAME_USE peUse);
                NativeMethods.ConvertSidToStringSid(pSid, out string strSid);

                results.Add(string.Format(
                    "{0} (SID : {1}, Type : {2})",
                    accountName,
                    strSid,
                    peUse.ToString()));
            }

            NativeMethods.LsaFreeMemory(EnumerationBuffer);

            return results;
        }


        public static IntPtr GetSystemLsaHandle(
            PolicyAccessRights policyAccess)
        {
            int error;
            int ntstatus;
            var lsaObjAttrs = new LSA_OBJECT_ATTRIBUTES();
            lsaObjAttrs.Length = Marshal.SizeOf(lsaObjAttrs);

            ntstatus = NativeMethods.LsaOpenPolicy(
                IntPtr.Zero,
                ref lsaObjAttrs,
                policyAccess,
                out IntPtr lsaHandle);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                error = NativeMethods.LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to get LSA handle.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return IntPtr.Zero;
            }

            return lsaHandle;
        }

        public static bool GrantSingleUserRight(
            IntPtr hLsa,
            string strSid,
            Rights right)
        {
            int error;
            int ntstatus;

            if (!NativeMethods.ConvertStringSidToSid(strSid, out IntPtr pSid))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to resolve SID ({0}).", strSid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            var privs = new LSA_UNICODE_STRING[1];
            privs[0] = new LSA_UNICODE_STRING(right.ToString());

            Console.WriteLine("[>] Trying to grant {0}.", right.ToString());

            ntstatus = NativeMethods.LsaAddAccountRights(hLsa, pSid, privs, 1);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                error = NativeMethods.LsaNtStatusToWinError(ntstatus);
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
            Rights right)
        {
            int error;
            int ntstatus;

            if (!NativeMethods.ConvertStringSidToSid(strSid, out IntPtr pSid))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to resolve SID ({0}).", strSid);
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            var privs = new LSA_UNICODE_STRING[1];
            privs[0] = new LSA_UNICODE_STRING(right.ToString());

            Console.WriteLine("[>] Trying to revoke {0}", right.ToString());

            ntstatus = NativeMethods.LsaRemoveAccountRights(hLsa, pSid, false, privs, 1);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                error = NativeMethods.LsaNtStatusToWinError(ntstatus);
                Console.WriteLine("[-] Failed to revoke right.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, true));

                return false;
            }

            Console.WriteLine("[+] {0} is revoked successfully.", right.ToString());

            return true;
        }
    }
}
