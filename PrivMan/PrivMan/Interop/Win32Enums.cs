using System;

namespace PrivMan.Interop
{
    [Flags]
    internal enum FileAccessFlags : uint
    {
        // Object Specific Rights
        AnyAccess = 0x00000000,
        ReadAccess = 0x00000001,
        WriteAccess = 0x00000002,
        ReadData = 0x00000001,
        ListDirectory = 0x00000001,
        WriteData = 0x00000002,
        AddFile = 0x00000002,
        AppendData = 0x00000004,
        AddSubdirectory = 0x00000004,
        CreatePipeInstance = 0x00000004,
        ReadEa = 0x00000008,
        WriteEa = 0x00000010,
        Execute = 0x00000020,
        Traverse = 0x00000020,
        DeleteChild = 0x00000040,
        ReadAttributes = 0x00000080,
        WriteAttributes = 0x00000100,
        AllAccess = 0x001F01FF,

        // Standard and Generic Rights
        Delete = 0x00010000,
        ReadControl = 0x00020000,
        WriteDac = 0x00040000,
        WriteOwner = 0x00080000,
        Synchronize = 0x00100000,
        StandardRithtsRequired = 0x000F0000,
        StandardRithtsRead = 0x00020000,
        StandardRithtsWrite = 0x00020000,
        StandardRithtsExecute = 0x00020000,
        StandardRithtsAll = 0x001F0000,
        SpecificRightsAll = 0x0000FFFF,
        AccessSystemSecurity = 0x01000000,
        MaximumAllowed = 0x02000000,
        GenericAll = 0x10000000,
        GenericExecute = 0x20000000,
        GenericWrite = 0x40000000,
        GenericRead = 0x80000000
    }

    internal enum FILE_ATTRIBUTE_FLAGS
    {
        None = 0x00000000,
        ReadOnly = 0x00000001,
        Hidden = 0x00000002,
        System = 0x00000004,
        Directory = 0x00000010,
        Archive = 0x00000020,
        Device = 0x00000040,
        Normal = 0x00000080,
        Temporary = 0x00000100,
        SparseFile = 0x00000200,
        ReparsePoint = 0x00000400,
        Compressed = 0x00000800,
        Offline = 0x00001000,
        NotContentIndexed = 0x00002000,
        Encrypted = 0x00004000,
        Virtual = 0x00010000,
        ValidFlags = 0x00007FB7,
        ValidSetFlags = 0x000031A7
    }


    [Flags]
    internal enum FILE_CREATE_OPTIONS : uint
    {
        None = 0x00000000,
        DirectoryFile = 0x00000001,
        WriteThrough = 0x00000002,
        SequentialOnly = 0x00000004,
        NoIntermediateBuffering = 0x00000008,
        SynchronousIoAlert = 0x00000010,
        SynchronousIoNonAlert = 0x00000020,
        NonDirectoryFile = 0x00000040,
        CreateTreeConnection = 0x00000080,
        CompleteIfOplocked = 0x00000100,
        NoEaKnowlege = 0x00000200,
        OpenForRecovery = 0x00000400,
        RandomAccess = 0x00000800,
        DeleteOnClose = 0x00001000,
        OpenByFileId = 0x00002000,
        OpenForBackupIntent = 0x00004000,
        NoCompression = 0x00008000,
        OpenRequiringOplock = 0x00010000,
        DisallowExclusive = 0x00020000,
        SessionAware = 0x00040000,
        ReserveOpFilter = 0x00100000,
        OpenReparsePoint = 0x00200000,
        OpenNoRecall = 0x00400000,
        OpenForFreeSpaceQuery = 0x00800000,
        CopyStructuredStorage = 0x00000041,
        StructuredStorage = 0x00000441
    }


    internal enum FILE_CREATE_DISPOSITION : uint
    {
        Supersede = 0,
        Open = 1,
        Create = 2,
        OpenIf = 3,
        Overwrite = 4,
        OverwriteIf = 5
    }


    [Flags]
    internal enum FILE_SHARE_ACCESS : uint
    {
        None = 0x00000000,
        Read = 0x00000001,
        Write = 0x00000002,
        Delete = 0x00000004,
        ValidFlags = 0x00000007
    }


    [Flags]
    internal enum OBJECT_ATTRIBUTES_FLAGS : uint
    {
        None = 0x00000000,
        ProtectClose = 0x00000001,
        Inherit = 0x00000002,
        AuditObjectClose = 0x00000004,
        NoEightsUpgrade = 0x00000008,
        Permanent = 0x00000010,
        Exclusive = 0x00000020,
        CaseInsensitive = 0x00000040,
        OpenIf = 0x00000080,
        OpenLink = 0x00000100,
        KernelHandle = 0x00000200,
        ForceAccessCheck = 0x00000400,
        IgnoreImpersonatedDeviceMap = 0x00000800,
        DontReparse = 0x00001000,
        ValieAttributes = 0x00001FF2
    }
}
