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

    internal enum XLAT_SIDE
    {
        SERVER = 1,
        CLIENT
    }
}
