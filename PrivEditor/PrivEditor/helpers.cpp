#include "pch.h"
#include "helpers.h"

ULONG GetFieldOffset(LPCSTR Type, LPCSTR Field, PULONG pOffset)
{
    FIELD_INFO flds = {
        (PUCHAR)Field,
        (PUCHAR)"",
        0,
        DBG_DUMP_FIELD_FULL_NAME | DBG_DUMP_FIELD_RETURN_ADDRESS,
        0,
        NULL };

    SYM_DUMP_PARAM Sym = {
       sizeof(SYM_DUMP_PARAM),
       (PUCHAR)Type,
       DBG_DUMP_NO_PRINT,
       0,
       NULL,
       NULL,
       NULL,
       1,
       &flds
    };

    ULONG Err;

    Sym.nFields = 1;
    Err = Ioctl(IG_DUMP_SYMBOL_INFO, &Sym, Sym.size);
    *pOffset = (ULONG)flds.FieldOffset;
    return Err;
}


BOOL IsKernelAddress(ULONG_PTR Address)
{
    if (IsPtr64()) {
        return (Address >= 0xffff080000000000ULL);
    }
    else {
        return (Address >= 0x80000000UL);
    }
}


BOOL IsPtr64()
{
    BOOL flag;
    ULONG dw;

    if (Ioctl(IG_IS_PTR64, &dw, sizeof(dw))) {
        flag = ((dw != 0) ? TRUE : FALSE);
    }
    else {
        flag = FALSE;
    }
    return flag;
}


ULONG ReadPointer(ULONG_PTR Address, PULONG_PTR Pointer)
{
    ULONG cb;
    if (IsPtr64()) {
        return (ReadMemory(Address, (PVOID)Pointer, sizeof(*Pointer), &cb) &&
            cb == sizeof(*Pointer));
    }
    else {
        ULONG Pointer32;
        ULONG Status;
        Status = ReadMemory(Address,
            (PVOID)&Pointer32,
            sizeof(Pointer32),
            &cb);
        if (Status && cb == sizeof(Pointer32)) {
            *Pointer = (ULONG64)(LONG64)(LONG)Pointer32;
            return 1;
        }
        return 0;
    }
}


ULONG ReadQword(ULONG_PTR Address, PULONG64 Pointer)
{
    ULONG cb;
    return (ReadMemory(Address, (PVOID)Pointer, 8, &cb) && cb == 8);
}


std::string ReadAnsiString(ULONG_PTR Address, int MaximumSize)
{
    std::string result;
    char buffer;
    ULONG cb;

    for (int idx = 0; idx < MaximumSize; idx++) {
        ReadMemory(Address + idx, &buffer, sizeof(char), &cb);
        if (buffer == '\0')
            break;
        else
            result.push_back(buffer);
    }

    return result;
}


std::wstring ReadUnicodeString(ULONG_PTR Address, int MaximumSize)
{
    std::wstring result;
    short buffer;
    ULONG cb;

    for (int idx = 0; idx < MaximumSize * 2; idx += 2) {
        ReadMemory(Address + idx, &buffer, sizeof(short), &cb);
        if (buffer == 0)
            break;
        else
            result.push_back(buffer);
    }

    return result;
}


ULONG WritePointer(ULONG_PTR Address, ULONG_PTR Pointer)
{
    ULONG cb;
    if (IsPtr64()) {
        return (WriteMemory(Address, &Pointer, sizeof(Pointer), &cb) &&
            cb == sizeof(Pointer));
    }
    else {
        ULONG Pointer32 = (ULONG)Pointer;
        ULONG Status;
        Status = WriteMemory(Address,
            &Pointer32,
            sizeof(Pointer32),
            &cb);
        return (Status && cb == sizeof(Pointer32)) ? 1 : 0;
    }
}


ULONG WriteQword(ULONG_PTR Address, ULONG64 Pointer)
{
    ULONG cb;
    return (WriteMemory(Address, &Pointer, 8, &cb) && cb == 8);
}
