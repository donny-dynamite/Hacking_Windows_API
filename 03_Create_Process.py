"""
Create process for cmd.exe using CreateProcessW()

[+] manually packed structs, even for unneeded SECURITY_ATTRIBUTES for completeness

[+] PowerShell script to verify TID/PID from CreateProcessW():
- PID match, via Get-Process
- TID match, via (Get-Process -ID $pid).Threads | ? {$_.Id -eq $tid}

"""

import ctypes
from ctypes import wintypes
from ctypes.wintypes import HANDLE,DWORD,LPWSTR,WORD,LPBYTE,LPVOID,BOOL
import subprocess
import sys

kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error = True)


######################################################
##### Manual struct packing for CreateProcessW() #####
######################################################
#
# Note:
# -----
# following will not actually be used here for func() call
# - lpProcessAttributes
# - lpThreadAttributes
#
# will be passed as None (NULL) -> so can be given c_void_p type in func() sig
# however both are pointers to SECURITY_ATTRIBUTES struct, so struct will be packed for completeness

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength",                 DWORD),
        ("lpSecurityDescriptor",    LPVOID),
        ("bInheritHandle",          BOOL),
    ]

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb",                DWORD),
        ("lpReserved",        LPWSTR),
        ("lpDesktop",         LPWSTR),
        ("lpTitle",           LPWSTR),
        ("dwX",               DWORD),
        ("dwY",               DWORD),
        ("dwXSize",           DWORD),
        ("dwYSize",           DWORD),
        ("dwXCountChars",     DWORD),
        ("dwYCountChars",     DWORD),
        ("dwFillAttribute",   DWORD),
        ("dwFlags",           DWORD),
        ("wShowWindow",       WORD),
        ("cbReserved2",       WORD),
        ("lpReserved2",       LPBYTE),
        ("hStdInput",         HANDLE),
        ("hStdOutput",        HANDLE),
        ("hStdError",         HANDLE),
    ]

class PROCESS_INFORMATION (ctypes.Structure):
    _fields_ = [
        ("hProcess",    HANDLE),
        ("hThread",     HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId",  DWORD),    
    ]


############################
##### CreateProcessW() #####
############################
#
#https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw

# def func() signatures
kernel32.CreateProcessW.argtypes =[
    wintypes.LPCWSTR,                       # lpApplicationName
    wintypes.LPWSTR,                        # lpCommandLine
    ctypes.POINTER(SECURITY_ATTRIBUTES),    # lpProcessAttributes
    ctypes.POINTER(SECURITY_ATTRIBUTES),    # lpThreadAttributes
    wintypes.BOOL,                          # bInheritHandles
    wintypes.DWORD,                         # dwCreationFlags
    ctypes.c_void_p,                        # lpEnvironment
    wintypes.LPCWSTR,                       # lpCurrentDirectory
    ctypes.POINTER(STARTUPINFOW),           # lpStartupInfo
    ctypes.POINTER(PROCESS_INFORMATION),    # lpProcessInformation
]
kernel32.CreateProcessW.restype = wintypes.BOOL


# def func() parameters
g_lpApplicationName = r"c:\windows\system32\cmd.exe"
g_lpCommandLine = None
g_lpProcessAttributes = None
g_lpThreadAttributes = None
g_bInheritHandles = False
g_dwCreationFlags = 0x10    # CREATE_NEW_CONSOLE
g_lpEnvironment = None
g_lpCurrentDirectory = None
g_lpStartupInfo = STARTUPINFOW()
g_lpProcessInformation = PROCESS_INFORMATION()


# func() wrapper for CreateProcessW()
def create_process(lpApplicationName,
                   lpCommandLine,
                   lpProcessAttributes, 
                   lpThreadAttributes, 
                   bInheritHandles, 
                   dwCreationFlags, 
                   lpEnvironment, 
                   lpCurrentDirectory, 
                   lpStartupInfo, 
                   lpProcessInformation):
    ret = kernel32.CreateProcessW(lpApplicationName,
                   lpCommandLine,
                   lpProcessAttributes, 
                   lpThreadAttributes, 
                   bInheritHandles, 
                   dwCreationFlags, 
                   lpEnvironment, 
                   lpCurrentDirectory, 
                   ctypes.byref(lpStartupInfo), 
                   ctypes.byref(lpProcessInformation)
                )

    if not ret:
        raise ctypes.WinError()
    return ret


# PowerShell func() to check match for PID/TID ret from CreateProcessW()
# messy, but works
def ps_script(pid, tid):

    print("\n***************************************")
    print("\tPowerShell double-check")
    print("***************************************")
    
    # confirm PID is associated with cmd.exe
    proc_check = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
        f"Get-Process -ID {pid}"],
        capture_output = True, text = True
    )
    print("\n[+] Process Info:")
    print(f"PS> Get-Process -ID {pid}\n-----------------------\n")
    print(f"{proc_check.stdout.strip()}")
    
    # confirm TID match on that returned from CreateProcessW(), as proc will have many un-related threads
    thread_check = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
        f"(Get-Process -ID {pid}).Threads | ? {{ $_.Id -eq {tid} }}"],
        capture_output = True, text = True
    )
    print(f"\n[+] Thread Info:")
    print(f"PS> (Get-Process -ID {pid}).Threads | Where-Object {{ $_.Id -eq {tid} }}")
    print("----------------------------------------------------------------------\n")
    print(f"{thread_check.stdout.strip()}\n")




# main func() try/except
try:
    p_create = create_process(g_lpApplicationName,
                   g_lpCommandLine,
                   g_lpProcessAttributes, 
                   g_lpThreadAttributes, 
                   g_bInheritHandles, 
                   g_dwCreationFlags, 
                   g_lpEnvironment, 
                   g_lpCurrentDirectory, 
                   g_lpStartupInfo, 
                   g_lpProcessInformation)
    print(f"\n[+] CreateProcessW() Successful, Application: {g_lpApplicationName}")
    print(f"\tProcess ID: {g_lpProcessInformation.dwProcessId}")
    print(f"\tThread ID: {g_lpProcessInformation.dwThreadId}")
    
    # run double-check using PowerShell
    pid = g_lpProcessInformation.dwProcessId
    tid = g_lpProcessInformation.dwThreadId
    ps_script(pid,tid)
    
except OSError as e:
    sys.exit(f"\n[!] CreateProcessW() Failed, Error: {e}")
        
finally:
    print("[+] Cleaning up handles\n-----------------------")

    if g_lpProcessInformation.hProcess not in (None, 0):
        kernel32.CloseHandle(g_lpProcessInformation.hProcess)
        print("[.] CloseHandle() on .hProcess Successful")
    else:
        print(f"[!] CloseHandle() Failed, Error: {ctypes.get_last_error()}")
    
    if g_lpProcessInformation.hThread not in (None, 0):
        kernel32.CloseHandle(g_lpProcessInformation.hThread)
        print("[.] CloseHandle() on .hThread Successful")
    else:
        print(f"[!] CloseHandle() Failed, Error: {ctypes.get_last_error()}")
