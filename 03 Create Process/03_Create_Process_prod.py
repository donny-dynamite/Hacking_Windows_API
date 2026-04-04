"""
Spawn cmd.exe using CreateProcessW()

Alternatively:
- spawn other process (eg, notepad.exe)
- run command line (eg, cmd.exe /k whoami /all)
"""

import ctypes
from ctypes import wintypes


kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)


# ----------------------------------
# CONSTANTS
# ----------------------------------

# for CreateProcessW() - samples
CREATE_NEW_CONSOLE  = 0x10
CREATE_NO_WINDOW    = 0x08000000
DETACHED_PROCESS    = 0x08




# ----------------------------------
# Struct Definitions
# ----------------------------------

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength",                 wintypes.DWORD),
        ("lpSecurityDescriptor",    wintypes.LPVOID),
        ("bInheritHandle",          wintypes.BOOL),
    ]

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

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess",    wintypes.HANDLE),
        ("hThread",     wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId",  wintypes.DWORD),    
    ]




# ----------------------------------
# Function Prototypes
# ----------------------------------

kernel32.CloseHandle.argtypes = [ wintypes.HANDLE, ]  # hObject
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.CreateProcessW.argtypes =[
    wintypes.LPCWSTR,                       # lpApplicationName (opt)
    wintypes.LPWSTR,                        # [i/o] lpCommandLine (opt)
    ctypes.POINTER(SECURITY_ATTRIBUTES),    # lpProcessAttributes (opt)
    ctypes.POINTER(SECURITY_ATTRIBUTES),    # lpThreadAttributes (opt)
    wintypes.BOOL,                          # bInheritHandles
    wintypes.DWORD,                         # dwCreationFlags
    ctypes.c_void_p,                        # lpEnvironment (opt)
    wintypes.LPCWSTR,                       # lpCurrentDirectory (opt)
    ctypes.POINTER(STARTUPINFOW),           # lpStartupInfo
    ctypes.POINTER(PROCESS_INFORMATION),    # [o] lpProcessInformation
]
kernel32.CreateProcessW.restype = wintypes.BOOL




# ----------------------------------
# Function Definitions
# ----------------------------------

def winerr() -> OSError:
    """ Return a ctypes.WinError() with the last Windows API error """
    return ctypes.WinError(ctypes.get_last_error())




def close_handle(handle: wintypes.HANDLE, name: str="Handle") -> None:
    """ Close open handles, to avoid resource leaks """

    print(f"\n[+] Closing Handle to {name}... ", end='', flush=True)

    if handle is None or handle.value == 0:
        print(f"[!] Warning: {name} is None or invalid, nothing to close")
        return

    if not kernel32.CloseHandle(handle):
        print(f"Failed! {name} handle: {handle}, Error: {winerr()}")
    else:
        print(f"Successful -> {name} handle: {handle.value}")




def create_process(app: str=r"c:\windows\system32\cmd.exe",
                   cmd: str=None,
                   flags: int=CREATE_NEW_CONSOLE
                  ) -> tuple[int, int, str]:
    """
    Create a new process using CreateProcessW()
    
    Args:
    -----
    app (str): full path to executable
    cmd (str): command line to execute -> conv. to mutable buffer
               - raw-string is immutable, stored in r/o memory
               - access-violation risk if CreateProcessW() attempts write
    flags (int): process creation flags, eg CREATE_NO_WINDOW
    """
    
    lpApplicationName = app
    lpCommandLine = ctypes.create_unicode_buffer(cmd) if cmd else None
    lpProcessAttributes = None
    lpThreadAttributes = None
    bInheritHandles = False
    dwCreationFlags = flags
    lpEnvironment = None
    lpCurrentDirectory = None

    lpStartupInfo = STARTUPINFOW()
    lpStartupInfo.cb = ctypes.sizeof(STARTUPINFOW)

    lpProcessInformation = PROCESS_INFORMATION()


    try:
        if not kernel32.CreateProcessW(lpApplicationName,
                       lpCommandLine,
                       lpProcessAttributes, 
                       lpThreadAttributes, 
                       bInheritHandles, 
                       dwCreationFlags, 
                       lpEnvironment, 
                       lpCurrentDirectory, 
                       ctypes.byref(lpStartupInfo), 
                       ctypes.byref(lpProcessInformation)):
            raise winerr()

        # for when passing in cmd, and where app=None
        executed_process = app if app else cmd

        # print information for Handles -> process / thread

        print("\n\n# " + "-" * 40)
        print(f"[+] CreateProcessW() Successful -> {executed_process}")
        print("# " + "-" * 40)
        
        print(f"-> Handle to Process: {lpProcessInformation.hProcess}")
        print(f"-> Handle to Thread: {lpProcessInformation.hThread}")

        # return for ProcessId / ThreadId
        pid = lpProcessInformation.dwProcessId
        tid = lpProcessInformation.dwThreadId

        return pid, tid, executed_process
        
    except OSError as e:
        raise OSError(f"\n[!] CreateProcessW() Failed, Application: {app}, Error: {e}")
            
    finally:
        hProcess = wintypes.HANDLE(lpProcessInformation.hProcess)
        if hProcess.value != 0:
            close_handle(hProcess, "Process")

        hThread = wintypes.HANDLE(lpProcessInformation.hThread)
        if hThread.value != 0:
            close_handle(hThread, "Thread")




def print_process_info(pid: int, tid: int, app: str) -> None:
    print(f"\n[+] Process Information")
    print(f"-> Application: {app}")
    print(f"-> Process Id: {pid}")
    print(f"-> Thread Id: {tid}")




##########################################
##### Main functionality starts here #####
##########################################

# ----------------------------------
# default call - spawn cmd.exe
# ----------------------------------
'''
pid, tid, app = create_process()
print_process_info(pid, tid, app)
'''

# ----------------------------------
# pass specific application - full path
# ----------------------------------
'''
app = r"c:\windows\system32\notepad.exe"
pid, tid, app = create_process(app=app)
print_process_info(pid, tid, app)
'''

# ----------------------------------
# pass-in a specific command line
# ----------------------------------

# app=None intentional, as cmd="" specified
cmd = r"cmd.exe /k whoami /all"
pid, tid, app = create_process(app=None, cmd=cmd)
print_process_info(pid, tid, app)
