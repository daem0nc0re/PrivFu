#pragma once

BOOL IsKernelAddress(ULONG64);
std::string PointerToString(ULONG64);
std::string ReadAnsiString(ULONG64, LONG);
BOOL ReadQword(ULONG64 Address, PULONG64 Value);
std::string ReadUnicodeString(ULONG64, LONG);
BOOL WriteQword(ULONG64 Address, ULONG64 Value);
