#pragma once

ULONG GetFieldOffset(LPCSTR Type, LPCSTR Field, PULONG pOffset);
BOOL IsPtr64();
BOOL IsKernelAddress(ULONG_PTR Address);
ULONG ReadPointer(ULONG_PTR Address, PULONG_PTR Pointer);
ULONG ReadQword(ULONG_PTR Address, PULONG64 Pointer);
std::string ReadAnsiString(ULONG_PTR Address, int MaximumSize);
std::wstring ReadUnicodeString(ULONG_PTR Address, int MaximumSize);
ULONG WritePointer(ULONG_PTR Address, ULONG_PTR Pointer);
ULONG WriteQword(ULONG_PTR Address, ULONG64 Pointer);
