using System;

namespace WfpTokenDup.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        /*
         * NTSTATUS
         */
        public const NTSTATUS STATUS_SUCCESS = 0;
        public const NTSTATUS STATUS_TIMEOUT = 0x00000102;
        public const NTSTATUS STATUS_MORE_ENTRIES = 0x00000105;
        public static readonly NTSTATUS STATUS_BUFFER_OVERFLOW = Convert.ToInt32("0x80000005", 16);
        public static readonly NTSTATUS STATUS_UNSUCCESSFUL = Convert.ToInt32("0xC0000001", 16);
        public static readonly NTSTATUS STATUS_INFO_LENGTH_MISMATCH = Convert.ToInt32("0xC0000004", 16);
        public static readonly NTSTATUS STATUS_BUFFER_TOO_SMALL = Convert.ToInt32("0xC0000023", 16);
        public static readonly NTSTATUS STATUS_NO_SUCH_LOGON_SESSION = Convert.ToInt32("0xC000005F", 16);
        public static readonly NTSTATUS STATUS_PRIVILEGE_NOT_HELD = Convert.ToInt32("0xC0000061", 16);
        public static readonly NTSTATUS STATUS_NOT_FOUND = Convert.ToInt32("0xC0000225", 16);

        /*
         * Win32 Error
         */
        public const int ERROR_SUCCESS = 0;

        /*
         * WTS Consts
         */
        public static readonly IntPtr WTS_CURRENT_SERVER = IntPtr.Zero;
        public static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;
        public static readonly string WTS_CURRENT_SERVER_NAME = null;
        public const int WTS_CURRENT_SESSION = -1;
        public const int WTS_ANY_SESSION = -2;

        /*
         * Known Guid
         */
        public static readonly Guid FWPM_PROVIDER_IKEEXT = new Guid("10ad9216-ccde-456c-8b16-e9f04e60a90b");
        public static readonly Guid FWPM_CONDITION_IP_LOCAL_ADDRESS = new Guid("d9ee00de-c1ef-4617-bfe3-ffd8f5a08957");
        public static readonly Guid FWPM_CONDITION_IP_REMOTE_ADDRESS = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");

        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        /*
         * Well-Known IPSEC_AUTH_TRANSFORM_ID
         */
        public static readonly IPSEC_AUTH_TRANSFORM_ID0 IPSEC_AUTH_TRANSFORM_ID_HMAC_MD5_96 = new IPSEC_AUTH_TRANSFORM_ID0
        {
            authType = IPSEC_AUTH_TYPE.MD5,
            authConfig = IPSEC_AUTH_CONFIG.HMAC_MD5_96
        };
        public static readonly IPSEC_AUTH_TRANSFORM_ID0 IPSEC_AUTH_TRANSFORM_ID_HMAC_SHA_1_96 = new IPSEC_AUTH_TRANSFORM_ID0
        {
            authType = IPSEC_AUTH_TYPE.SHA_1,
            authConfig = IPSEC_AUTH_CONFIG.HMAC_SHA_1_96
        };
        public static readonly IPSEC_AUTH_TRANSFORM_ID0 IPSEC_AUTH_TRANSFORM_ID_HMAC_SHA_256_128 = new IPSEC_AUTH_TRANSFORM_ID0
        {
            authType = IPSEC_AUTH_TYPE.SHA_256,
            authConfig = IPSEC_AUTH_CONFIG.HMAC_SHA_256_128
        };
        public static readonly IPSEC_AUTH_TRANSFORM_ID0 IPSEC_AUTH_TRANSFORM_ID_GCM_AES_128 = new IPSEC_AUTH_TRANSFORM_ID0
        {
            authType = IPSEC_AUTH_TYPE.AES_128,
            authConfig = IPSEC_AUTH_CONFIG.GCM_AES_128
        };
        public static readonly IPSEC_AUTH_TRANSFORM_ID0 IPSEC_AUTH_TRANSFORM_ID_GCM_AES_192 = new IPSEC_AUTH_TRANSFORM_ID0
        {
            authType = IPSEC_AUTH_TYPE.AES_192,
            authConfig = IPSEC_AUTH_CONFIG.GCM_AES_192
        };
        public static readonly IPSEC_AUTH_TRANSFORM_ID0 IPSEC_AUTH_TRANSFORM_ID_GCM_AES_256 = new IPSEC_AUTH_TRANSFORM_ID0
        {
            authType = IPSEC_AUTH_TYPE.AES_256,
            authConfig = IPSEC_AUTH_CONFIG.GCM_AES_256
        };

        /*
         * Well-Known IPSEC_CIPHER_TRANSFORM_ID0
         */
        public static readonly IPSEC_CIPHER_TRANSFORM_ID0 IPSEC_CIPHER_TRANSFORM_ID_CBC_DES = new IPSEC_CIPHER_TRANSFORM_ID0
        {
            cipherType = IPSEC_CIPHER_TYPE.DES,
            cipherConfig = IPSEC_CIPHER_CONFIG.CBC_DES
        };
        public static readonly IPSEC_CIPHER_TRANSFORM_ID0 IPSEC_CIPHER_TRANSFORM_ID_CBC_3DES = new IPSEC_CIPHER_TRANSFORM_ID0
        {
            cipherType = IPSEC_CIPHER_TYPE.TRIPLE_DES,
            cipherConfig = IPSEC_CIPHER_CONFIG.CBC_3DES
        };
        public static readonly IPSEC_CIPHER_TRANSFORM_ID0 IPSEC_CIPHER_TRANSFORM_ID_AES_128 = new IPSEC_CIPHER_TRANSFORM_ID0
        {
            cipherType = IPSEC_CIPHER_TYPE.AES_128,
            cipherConfig = IPSEC_CIPHER_CONFIG.CBC_AES_128
        };
        public static readonly IPSEC_CIPHER_TRANSFORM_ID0 IPSEC_CIPHER_TRANSFORM_ID_AES_192 = new IPSEC_CIPHER_TRANSFORM_ID0
        {
            cipherType = IPSEC_CIPHER_TYPE.AES_192,
            cipherConfig = IPSEC_CIPHER_CONFIG.CBC_AES_192
        };
        public static readonly IPSEC_CIPHER_TRANSFORM_ID0 IPSEC_CIPHER_TRANSFORM_ID_AES_256 = new IPSEC_CIPHER_TRANSFORM_ID0
        {
            cipherType = IPSEC_CIPHER_TYPE.AES_256,
            cipherConfig = IPSEC_CIPHER_CONFIG.CBC_AES_256
        };
        public static readonly IPSEC_CIPHER_TRANSFORM_ID0 IPSEC_CIPHER_TRANSFORM_ID_GCM_AES_128 = new IPSEC_CIPHER_TRANSFORM_ID0
        {
            cipherType = IPSEC_CIPHER_TYPE.AES_128,
            cipherConfig = IPSEC_CIPHER_CONFIG.GCM_AES_128
        };
        public static readonly IPSEC_CIPHER_TRANSFORM_ID0 IPSEC_CIPHER_TRANSFORM_ID_GCM_AES_192 = new IPSEC_CIPHER_TRANSFORM_ID0
        {
            cipherType = IPSEC_CIPHER_TYPE.AES_192,
            cipherConfig = IPSEC_CIPHER_CONFIG.GCM_AES_192
        };
        public static readonly IPSEC_CIPHER_TRANSFORM_ID0 IPSEC_CIPHER_TRANSFORM_ID_GCM_AES_256 = new IPSEC_CIPHER_TRANSFORM_ID0
        {
            cipherType = IPSEC_CIPHER_TYPE.AES_256,
            cipherConfig = IPSEC_CIPHER_CONFIG.GCM_AES_256
        };

        /*
         * Privilege Name
         */
        public const string SE_DEBUG_NAME = "SeDebugPrivilege";
        public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";
        public const string SE_TCB_NAME = "SeTcbPrivilege";

        /*
         * Socket
         */
        public const int SOCKET_ERROR = -1;
        public static readonly IntPtr INVALID_SOCKET = new IntPtr(-1);
    }
}
