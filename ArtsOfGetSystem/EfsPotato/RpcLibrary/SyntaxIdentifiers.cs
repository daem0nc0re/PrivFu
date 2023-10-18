using System;

namespace RpcLibrary
{
    internal class SyntaxIdentifiers
    {
        public static readonly RPC_SYNTAX_IDENTIFIER RpcUuidSyntax_1_0 = new RPC_SYNTAX_IDENTIFIER
        {
            SyntaxGUID = new Guid("12345678-1234-ABCD-EF00-0123456789AB"),
            SyntaxVersion = new RPC_VERSION { MajorVersion = 1, MinorVersion = 0 }
        };
        public static readonly RPC_SYNTAX_IDENTIFIER RpcTransferSyntax_2_0 = new RPC_SYNTAX_IDENTIFIER
        {
            SyntaxGUID = new Guid("8A885D04-1CEB-11C9-9FE8-08002B104860"),
            SyntaxVersion = new RPC_VERSION { MajorVersion = 2, MinorVersion = 0 }
        };
        public static readonly RPC_SYNTAX_IDENTIFIER RpcTransferSyntax64_2_0 = new RPC_SYNTAX_IDENTIFIER
        {
            SyntaxGUID = new Guid("71710533-BEBA-4937-8319-B5DBEF9CCC36"),
            SyntaxVersion = new RPC_VERSION { MajorVersion = 1, MinorVersion = 0 }
        };
        public static readonly RPC_SYNTAX_IDENTIFIER SyncControllerSyntax_1_0 = new RPC_SYNTAX_IDENTIFIER
        {
            SyntaxGUID = new Guid("923C9623-DB7F-4B34-9E6D-E86580F8CA2A"),
            SyntaxVersion = new RPC_VERSION { MajorVersion = 1, MinorVersion = 0 }
        };
        /*
         * UUID reference:
         * * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/1baaad2f-7a84-4238-b113-f32827a39cd2
         * * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/ab3c0be4-5b55-4a08-b198-f17170100be6
         */
        public static readonly RPC_SYNTAX_IDENTIFIER LsarUuidSyntax_1_0 = new RPC_SYNTAX_IDENTIFIER
        {
            SyntaxGUID = new Guid("C681D488-D850-11D0-8C52-00C04FD90F7E"),
            SyntaxVersion = new RPC_VERSION { MajorVersion = 1, MinorVersion = 0 }
        };
        public static readonly RPC_SYNTAX_IDENTIFIER EfsrUuidSyntax_1_0 = new RPC_SYNTAX_IDENTIFIER
        {
            SyntaxGUID = new Guid("DF1941C5-FE89-4E79-BF10-463657ACF44D"),
            SyntaxVersion = new RPC_VERSION { MajorVersion = 1, MinorVersion = 0 }
        };
        public static readonly RPC_SYNTAX_IDENTIFIER SamrUuidSyntax_1_0 = new RPC_SYNTAX_IDENTIFIER
        {
            SyntaxGUID = new Guid("C681D488-D850-11D0-8C52-00C04FD90F7E"),
            SyntaxVersion = new RPC_VERSION { MajorVersion = 1, MinorVersion = 0 }
        };
        public static readonly RPC_SYNTAX_IDENTIFIER LsassUuidSyntax_1_0 = new RPC_SYNTAX_IDENTIFIER
        {
            SyntaxGUID = new Guid("C681D488-D850-11D0-8C52-00C04FD90F7E"),
            SyntaxVersion = new RPC_VERSION { MajorVersion = 1, MinorVersion = 0 }
        };
        public static readonly RPC_SYNTAX_IDENTIFIER NetlogonUuidSyntax_1_0 = new RPC_SYNTAX_IDENTIFIER
        {
            SyntaxGUID = new Guid("C681D488-D850-11D0-8C52-00C04FD90F7E"),
            SyntaxVersion = new RPC_VERSION { MajorVersion = 1, MinorVersion = 0 }
        };
    }
}
