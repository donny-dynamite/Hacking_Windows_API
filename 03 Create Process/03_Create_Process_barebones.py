"""
Spawn cmd.exe using CreateProcessW()
"""

import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)

# Struct Definitions -> required by CreateProcessW()
class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb",                wintypes.DWORD),
        ("lpReserved",        wintypes.LPWSTR),
        ("lpDesktop",         wintypes.LPWSTR),
        ("lpTitle",           wintypes.LPWSTR),
        ("dwX",               wintypes.DWORD),
        ("dwY",               wintypes.DWORD),
        ("dwXSize",           wintypes.DWORD),
        ("dwYSize",           wintypes.DWORD),
        ("dwXCountChars",     wintypes.DWORD),
        ("dwYCountChars",     wintypes.DWORD),
        ("dwFillAttribute",   wintypes.DWORD),
        ("dwFlags",           wintypes.DWORD),
        ("wShowWindow",       wintypes.WORD),
        ("cbReserved2",       wintypes.WORD),
        ("lpReserved2",       wintypes.LPBYTE),
        ("hStdInput",         wintypes.HANDLE),
        ("hStdOutput",        wintypes.HANDLE),
        ("hStdError",         wintypes.HANDLE),
]

class PROCESS_INFORMATION (ctypes.Structure):
    _fields_ = [
        ("hProcess",    wintypes.HANDLE),
        ("hThread",     wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId",  wintypes.DWORD),
]

# ----------------------------------
# Main functionality starts here
# ----------------------------------

lpApplicationName = r"c:\windows\system32\cmd.exe"
kernel32.CreateProcessW(lpApplicationName, None, None, None, False, 0x10, None, None, 
                   ctypes.byref(STARTUPINFOW()), 
                   ctypes.byref(PROCESS_INFORMATION())
)
