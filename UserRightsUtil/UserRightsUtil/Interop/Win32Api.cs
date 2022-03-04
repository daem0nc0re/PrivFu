using System;
using System.Runtime.InteropServices;
using System.Text;

namespace UserRightsUtil.Interop
{
    class Win32Api
    {
        /*
         * advapi32.dll
         */
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool ConvertStringSidToSid(string StringSid, out IntPtr pSid);

        [DllImport("advapi32.dll")]
        public static extern uint GetLengthSid(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool IsValidSid(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupAccountName(
            string lpSystemName,
            string lpAccountName,
            IntPtr Sid,
            ref int cbSid,
            StringBuilder ReferencedDomainName,
            ref int cchReferencedDomainName,
            out Win32Const.SID_NAME_USE peUse);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupAccountSid(
            string strSystemName,
            IntPtr pSid,
            StringBuilder pName,
            ref int cchName,
            StringBuilder pReferencedDomainName,
            ref int cchReferencedDomainName,
            out Win32Const.SID_NAME_USE peUse);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint LsaAddAccountRights(
            IntPtr PolicyHandle,
            IntPtr pSID,
            Win32Struct.LSA_UNICODE_STRING[] UserRights,
            int CountOfRights);

        [DllImport("advapi32.dll")]
        public static extern uint LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint LsaEnumerateAccountRights(
            IntPtr PolicyHandle,
            IntPtr pSID,
            out IntPtr UserRights, // LSA_UNICODE_STRING[]
            out ulong CountOfRights);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint LsaEnumerateAccountsWithUserRight(
            IntPtr PolicyHandle,
            Win32Struct.LSA_UNICODE_STRING[] UserRights,
            out IntPtr EnumerationBuffer,
            out int CountReturned);

        [DllImport("advapi32.dll")]
        public static extern uint LsaFreeMemory(IntPtr Buffer);

        [DllImport("advapi32.dll")]
        public static extern int LsaNtStatusToWinError(uint NtStatus);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint LsaOpenPolicy(
            IntPtr SystemName, // Win32Struct.LSA_UNICODE_STRING[]
            ref Win32Struct.LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            Win32Const.PolicyAccessRights AccessMask,
            out IntPtr PolicyHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint LsaRemoveAccountRights(
            IntPtr PolicyHandle,
            IntPtr pSID,
            bool AllRights,
            Win32Struct.LSA_UNICODE_STRING[] UserRights,
            int CountOfRights);

        /*
         * kenel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint FormatMessage(
            Win32Const.FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FreeLibrary(IntPtr hLibModule);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);

        /*
         * netapi32.dll
         */
        [DllImport("netapi32.dll")]
        public static extern uint NetApiBufferFree(IntPtr Buffer);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        public static extern uint NetLocalGroupEnum(
            string servername,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        public static extern uint NetUserGetLocalGroups(
            string servername,
            string username,
            int level,
            int flags,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries);
    }
}
