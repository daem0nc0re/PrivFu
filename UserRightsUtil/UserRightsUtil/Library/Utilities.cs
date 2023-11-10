using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using UserRightsUtil.Interop;

namespace UserRightsUtil.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static bool GetUserRights(IntPtr pSid, out List<Rights> rights)
        {
            IntPtr hLsa;
            string accountName = Helpers.ConvertSidToAccountName(
                pSid,
                out SID_NAME_USE peUse);
            var status = false;
            rights = new List<Rights>();

            if (string.IsNullOrEmpty(accountName))
                return false;

            hLsa = GetSystemLsaHandle(PolicyAccessRights.POLICY_LOOKUP_NAMES);

            if (hLsa == IntPtr.Zero)
                return false;

            do
            {
                string groupName;
                int nUnitSize = Marshal.SizeOf(typeof(LSA_UNICODE_STRING));
                var pResumeHandle = IntPtr.Zero;
                NTSTATUS ntstatus = NativeMethods.LsaEnumerateAccountRights(
                    hLsa,
                    pSid,
                    out IntPtr pUserRightsBuffer,
                    out uint nUserRightsCount);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                {
                    for (var idx = 0; idx < (int)nUserRightsCount; idx++)
                    {
                        IntPtr pUserRight;

                        if (Environment.Is64BitProcess)
                            pUserRight = new IntPtr(pUserRightsBuffer.ToInt64() + (idx * nUnitSize));
                        else
                            pUserRight = new IntPtr(pUserRightsBuffer.ToInt32() + (idx * nUnitSize));

                        var userRight = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                            pUserRight,
                            typeof(LSA_UNICODE_STRING));
                        var right = (Rights)Enum.Parse(typeof(Rights), userRight.ToString());

                        if (!rights.Contains(right))
                            rights.Add(right);
                    }
                }

                if (peUse == SID_NAME_USE.Alias)
                    break;

                ntstatus = NativeMethods.NetUserGetLocalGroups(
                    Environment.MachineName,
                    accountName,
                    0,
                    Win32Consts.LG_INCLUDE_INDIRECT,
                    out IntPtr pLocalGroupUserInfo,
                    Win32Consts.MAX_PREFERRED_LENGTH,
                    out int _,
                    out int _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                ntstatus = NativeMethods.NetLocalGroupEnum(
                    Environment.MachineName,
                    0,
                    out IntPtr pLocalGroups,
                    Win32Consts.MAX_PREFERRED_LENGTH,
                    out int nEntries,
                    out int _,
                    ref pResumeHandle);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    NativeMethods.NetApiBufferFree(pLocalGroupUserInfo);
                    break;
                }

                groupName = Marshal.PtrToStringUni(Marshal.ReadIntPtr(pLocalGroupUserInfo));

                for (var idx = 0; idx < nEntries; idx++)
                {
                    IntPtr pAccountName = Marshal.ReadIntPtr(pLocalGroups, (idx * IntPtr.Size));
                    accountName = Marshal.PtrToStringUni(pAccountName);

                    if (Helpers.CompareIgnoreCase(accountName, groupName))
                    {
                        string stringSid = Helpers.ConvertAccountNameToStringSid(
                            ref accountName,
                            out SID_NAME_USE _);
                        NativeMethods.ConvertStringSidToSid(stringSid, out IntPtr pSidBytes);

                        ntstatus = NativeMethods.LsaEnumerateAccountRights(
                            hLsa,
                            pSidBytes,
                            out IntPtr pGroupRightsBuffer,
                            out uint nGroupRightsCount);
                        NativeMethods.LocalFree(pSidBytes);

                        if (ntstatus != Win32Consts.STATUS_SUCCESS)
                            break;

                        for (var num = 0; num < (int)nGroupRightsCount; num++)
                        {
                            IntPtr pGroupRight;

                            if (Environment.Is64BitProcess)
                                pGroupRight = new IntPtr(pGroupRightsBuffer.ToInt64() + (num * nUnitSize));
                            else
                                pGroupRight = new IntPtr(pGroupRightsBuffer.ToInt32() + (num * nUnitSize));

                            var groupRight = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                                pGroupRight,
                                typeof(LSA_UNICODE_STRING));
                            var right = (Rights)Enum.Parse(typeof(Rights), groupRight.ToString());

                            if (!rights.Contains(right))
                                rights.Add(right);
                        }
                    }
                }

                NativeMethods.NetApiBufferFree(pLocalGroups);
                NativeMethods.NetApiBufferFree(pLocalGroupUserInfo);
            } while (false);

            NativeMethods.LsaClose(hLsa);

            return status;
        }


        public static List<string> GetUsersWithRight(Rights right)
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


        public static IntPtr GetSystemLsaHandle(PolicyAccessRights policyAccess)
        {
            var lsaObjAttrs = new LSA_OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES))
            };
            NTSTATUS ntstatus = NativeMethods.LsaOpenPolicy(
                IntPtr.Zero,
                in lsaObjAttrs,
                policyAccess,
                out IntPtr lsaHandle);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                NativeMethods.SetLastError(NativeMethods.LsaNtStatusToWinError(ntstatus));
                lsaHandle = IntPtr.Zero;
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
