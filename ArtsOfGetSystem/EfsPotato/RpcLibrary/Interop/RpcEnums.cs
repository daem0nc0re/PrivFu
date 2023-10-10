using System;

namespace RpcLibrary.Interop
{
    internal enum IDL_CS_CONVERT
    {
        IDL_CS_NO_CONVERT,
        IDL_CS_IN_PLACE_CONVERT,
        IDL_CS_NEW_BUFFER_CONVERT
    }

    [Flags]
    internal enum MIDL_STUB_MESSAGE_FLAGS : uint
    {
        fInDontFree = 0x00000001,
        fDontCallFreeInst = 0x00000002,
        fUnused1 = 0x00000004,
        fHasReturn = 0x00000008,
        fHasExtensions = 0x00000010,
        fHasNewCorrDesc = 0x00000020,
        fIsIn = 0x00000040,
        fIsOut = 0x00000080,
        fIsOicf = 0x00000100,
        fBufferValid = 0x00000200,
        fHasMemoryValidateCallback = 0x00000400,
        fInFree = 0x00000800,
        fNeedMCCP = 0x00001000
    }

    [Flags]
    internal enum NDR64_ARRAY_FLAGS : byte
    {
        None = 0x00,
        HasPointerInfo = 0x01,
        HasElementInfo = 0x02,
        IsMultiDimensional = 0x04,
        IsArrayofStrings = 0x08,
        Reserved1 = 0x10,
        Reserved2 = 0x20,
        Reserved3 = 0x40,
        Reserved4 = 0x80
    }

    [Flags]
    internal enum NDR64_PARAM_FLAGS : ushort
    {
        MustSize = 0x0001,
        MustFree = 0x0002,
        IsPipe = 0x0004,
        IsIn = 0x0008,
        IsOut = 0x0010,
        IsReturn = 0x0020,
        IsBasetype = 0x0040,
        IsByValue = 0x0080,
        IsSimpleRef = 0x0100,
        IsDontCallFreeInst = 0x0200,
        SaveForAsyncFinish = 0x0400,
        IsPartialIgnore = 0x0800,
        IsForceAllocate = 0x1000,
        Reserved = 0x6000,
        UseCache = 0x8001
    }

    [Flags]
    internal enum NDR64_POINTER_REPEAT_FLAGS : byte
    {
        None = 0x00,
        SetCorrMark = 0x01
    }

    [Flags]
    internal enum NDR64_STRING_FLAGS : byte
    {
        IsSized = 0x01,
        IsRanged = 0x02,
        Reserved3 = 0x04,
        Reserved4 = 0x08,
        Reserved5 = 0x10,
        Reserved6 = 0x20,
        Reserved7 = 0x40,
        Reserved8 = 0x80
    }

    [Flags]
    internal enum NDR64_STRUCTURE_FLAGS : byte
    {
        HasPointerInfo = 0x01,
        HasMemberInfo = 0x02,
        HasConfArray = 0x04,
        HasOrigPointerInfo = 0x08,
        HasOrigMemberInfo = 0x10,
        Reserved1 = 0x20,
        Reserved2 = 0x40,
        Reserved3 = 0x80
    }

    internal enum RPC_C_AUTHN : uint
    {
        NONE = 0,
        DCE_PRIVATE = 1,
        DCE_PUBLIC = 2,
        DEC_PUBLIC = 4,
        GSS_NEGOTIATE = 9,
        WINNT = 10,
        GSS_SCHANNEL = 14,
        GSS_KERBEROS = 16,
        DPA = 17,
        MSN = 18,
        DIGEST = 21,
        KERNEL = 20,
        NEGO_EXTENDER = 30,
        PKU2U = 31,
        LIVE_SSP = 32,
        LIVEXP_SSP = 35,
        CLOUD_AP = 36,
        MSONLINE = 82,
        MQ = 100,
        DEFAULT = 0xFFFFFFFF
    }

    internal enum RPC_C_AUTHN_LEVEL : uint
    {
        DEFAULT = 0,
        NONE = 1,
        CONNECT = 2,
        CALL = 3,
        PKT = 4,
        PKT_INTEGRITY = 5,
        PKT_PRIVACY = 6
    }

    internal enum RPC_C_AUTHZ : uint
    {
        NONE = 0,
        NAME = 1,
        DCE = 2,
        DEFAULT = 0xFFFFFFFF
    }

    internal enum RPC_C_OPT : uint
    {
        MQ_DELIVERY = 1,
        MQ_PRIORITY = 2,
        MQ_JOURNAL = 3,
        MQ_ACKNOWLEDGE = 4,
        MQ_AUTHN_SERVICE = 5,
        MQ_AUTHN_LEVEL = 6,
        MQ_TIME_TO_REACH_QUEUE = 7,
        MQ_TIME_TO_BE_RECEIVED = 8,
        BINDING_NONCAUSAL = 9,
        SECURITY_CALLBACK = 10,
        UNIQUE_BINDING = 11,
        CALL_TIMEOUT = 12,
        DONT_LINGER = 13,
        TRUST_PEER = 14,
        ASYNC_BLOCK = 15,
        OPTIMIZE_TIME = 16,
        MAX_OPTIONS = 17
    }

    internal enum XLAT_SIDE
    {
        SERVER = 1,
        CLIENT
    }
}
