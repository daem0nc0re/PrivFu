#include "pch.h"
#include "helpers.h"

BOOL IsKernelAddress(ULONG64 Address)
{
    if (IsPtr64())
        return (Address >= 0xFFFF080000000000ULL);
    else
        return ((ULONG)Address >= 0x80000000UL);
}


std::string PointerToString(ULONG64 pointer)
{
    CHAR buffer[32] = { 0 };
    ULONG higher = (ULONG)((pointer >> 32) & 0xFFFFFFFFUL);
    ULONG lower = (ULONG)(pointer & 0xFFFFFFFFUL);

    if (IsPtr64())
        ::sprintf_s(buffer, 32, "0x%08x`%08x", higher, lower);
    else
        ::sprintf_s(buffer, 32, "0x%08x", lower);

    return std::string(buffer);
}


std::string ReadAnsiString(ULONG64 Address, LONG Size)
{
    std::string result;
    char charByte = 0;
    ULONG cb = 0;

    for (LONG idx = 0; idx < Size; idx++)
    {
        if (ReadMemory(Address + idx, &charByte, sizeof(char), &cb))
        {
            if (charByte == 0)
                break;
            else
                result.push_back(charByte);
        }
    }

    return result;
}


BOOL ReadQword(ULONG64 Address, PULONG64 Value)
{
    ULONG cb = 0UL;
    return ReadMemory(Address, Value, 8, &cb);
}


std::string ReadUnicodeString(ULONG64 Address, LONG Size)
{
    std::string result;
    std::wstring readString;
    ULONG nBufferSize;
    CHAR* charBuffer;
    ULONG cb = 0UL;
    SHORT unicode = 0;
    size_t retVal = 0;

    for (LONG idx = 0; idx < Size; idx += 2)
    {
        if (ReadMemory(Address + idx, &unicode, sizeof(short), &cb))
        {
            if (unicode == 0)
                break;
            else
                readString.push_back(unicode);
        }
        else
        {
            break;
        }
    }

    if (readString.length() > 0)
    {
        nBufferSize = (ULONG)readString.length() * 2;
        charBuffer = new CHAR[nBufferSize + 2];
        ::wcstombs_s(&retVal, charBuffer, nBufferSize, readString.c_str(), nBufferSize);
        result = std::string(charBuffer);
        delete[] charBuffer;
    }

    return result;
}


BOOL WriteQword(ULONG64 Address, ULONG64 Value)
{
    ULONG cb = 0UL;
    return WriteMemory(Address, &Value, 8, &cb);
}