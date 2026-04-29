"""
(prod) Open handle to Access Token for a given process

Steps:
------
- Choose PID from list (grouped by ProcessName)
- OpenProcess() for given PID
- OpenProcessToken() for returned process handle

"""

import ctypes
from ctypes import wintypes
from collections import defaultdict
from contextlib import contextmanager


# import DLLs
kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32.dll', use_last_error=True)


# ---------------------------------------------------
#                   CONSTANTS
# ---------------------------------------------------

# CreateToolhelp32Snapshot() - samlpes
INVALID_HANDLE_VALUE        = wintypes.HANDLE(-1)
TH32CS_SNAPPROCESS          = 0x02
TH32CS_SNAPTHREAD           = 0x04

# OpenProcess()
PROCESS_ALL_ACCESS  = 0x1F0FFF

# OpenProcessToken()
TOKEN_ALL_ACCESS    = 0xF01FF

# PROCESSENTRY32W() struct
MAX_PATH = 260


# ---------------------------------------------------
#               Struct Definitions
# ---------------------------------------------------

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize",              wintypes.DWORD),
        ("cntUsage",            wintypes.DWORD),
        ("th32ProcessID",       wintypes.DWORD),
        ("th32DefaultHeapID",   ctypes.c_size_t),
        ("th32ModuleID",        wintypes.DWORD),
        ("cntThreads",          wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase",      wintypes.LONG),
        ("dwFlags",             wintypes.DWORD),
        ("szExeFile",           wintypes.WCHAR * MAX_PATH)
]


# ---------------------------------------------------
#               Function Prototypes
# ---------------------------------------------------

# ----- kernel32.dll -----
kernel32.CloseHandle.argtypes = [wintypes.HANDLE,]  # hObject
kernel32.CloseHandle.restype = wintypes.BOOL


kernel32.CreateToolhelp32Snapshot.argtypes = [
    wintypes.DWORD,     # dwFlags
    wintypes.DWORD,     # th32ProcessID
]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE


kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,         # dwDesiredAccess
    wintypes.BOOL,          # bInheritHandle
    wintypes.DWORD,         # dwProcessId
]
kernel32.OpenProcess.restype = wintypes.HANDLE


kernel32.Process32FirstW.argtypes = [
    wintypes.HANDLE,                    # hSnapshot
    ctypes.POINTER(PROCESSENTRY32W),    # [o] lppe, proc-list entry from snapshot
]
kernel32.Process32FirstW.restype = wintypes.BOOL


kernel32.Process32NextW.argtypes = [
    wintypes.HANDLE,                    # hSnapshot
    ctypes.POINTER(PROCESSENTRY32W),    # [o] lppe, proc-list entry from snapshot
]
kernel32.Process32NextW.restype = wintypes.BOOL


# ----- advapi32.dll -----

advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE,                    # ProcessHandle
    wintypes.DWORD,                     # DesiredAccess
    ctypes.POINTER(wintypes.HANDLE),    # [o] TokenHandle
    ]
advapi32.OpenProcessToken.restype = wintypes.BOOL


# --------------------------------------------------
#               Function Definitions
# --------------------------------------------------

# ------------- Misc help functions ----------------

def winerr() -> OSError:
    """ return a ctypes.WinError() with last Windows API error """
    return ctypes.WinError(ctypes.get_last_error())


def close_handle(handle, name="Handle", id_number: int | None = None) -> None:
    """ Close open handles to avoid resource leaks """

    # ----- error checking
    if handle is None or handle.value == 0:
        raise ValueError(f"\n[!] Warning: {name} is None or invalid -> nothing to close")
        
    if not kernel32.CloseHandle(handle):
        raise winerr()
    
    
    # ----- if handle associated with a thread/process id
    if id_number:
        print(f"    -> Closed handle to {name}: ({handle.value}) [{name} ID: {id_number}]")
    else:
        print(f"    -> Closed handle to {name}: ({handle.value})")


def key_sort(name: str) -> str:
    """ Ensure processes sorted alphabetically, regardless of case """
    return name.casefold()


# --------------- Process Id information ---------------
# section added to replace the powerscript block for listing/grouping process id information


def group_pids_by_process() -> tuple[defaultdict[str, list[int]],
                                    dict[int, str]
                                ]:
    """
    Snapshot taken of running processes -> TH32CS_SNAPPROCESS
    - iterated by Process32FirstW -> Process32NextW, until empty

    Returns a numer of dictionaries later used for different purposes
    [+] proc_groups: 
    - defaultdict() of process names, and list of associated PIDs
    - for iteration of full-print out 

    [+] pid_to_proc_map: O(1)
    - PID validation, 1:1 of PID to process name
    """

    # proc_groups -> for iterating whole list in full print-out
    proc_groups: defaultdict[str, list[int]] = defaultdict(list)

    # pid_proc_map -> fast search for later-on PID validation
    pid_to_proc_map: dict[int, str] = {}

    pe32w = PROCESSENTRY32W()
    pe32w.dwSize = ctypes.sizeof(PROCESSENTRY32W)

    # Context Manager - snapshot
    with snapshot(TH32CS_SNAPPROCESS) as hSnapshot: 
        if not kernel32.Process32FirstW(hSnapshot, ctypes.byref(pe32w)):
            raise winerr()

        print("    -> Taking Snapshot: Running Processes... ", end='', flush=True)

        while True:
            name = pe32w.szExeFile      # process name
            pid  = pe32w.th32ProcessID  # leave PIDs as ints in list

            proc_groups[name].append(pid)
            pid_to_proc_map[pid] = name
                
            if not kernel32.Process32NextW(hSnapshot, ctypes.byref(pe32w)):
                break

        print("Completed")

    return proc_groups, pid_to_proc_map




def print_pids_by_process(process_groups: dict[str, list[int]]) -> None:
    """
    Print Process Names -> associated PIDs -> count of PIDs
    - sorted alphabetically, then numerically
    - PID list truncated if too long (eg svchost.exe)
    """

    # header info
    print(f"\n{'Process Name':<40} {'PID':<40} {'Count':>5}")
    print('-' * 87)


    for process_name in sorted(process_groups.keys(), key=key_sort):
        sorted_pids = sorted(process_groups[process_name])
        
        # join pids -> must first be converted to type str()
        pid_list_str = ', '.join(str(pid) for pid in sorted_pids)
        
        count = len(sorted_pids)
        
        # truncate long list of PIDs
        if len(pid_list_str) > 35:
            pid_list_str = pid_list_str[:35] + '...'
        
        print(f"{process_name:<40} {pid_list_str:<40} {count:<5}")




def request_pid(pid_map: dict[int, str]) -> int:
    """ Return positive integer -> later validate if actual PID """
    while True:
        try:
            pid = int(input("\nPlease enter a valid PID: "))
            if pid > 0:
                if validate_pid(pid, pid_map):
                    return pid
            else:
                print("[!] Please enter a positive integer: ")
        except ValueError as e:
            print(f"\n[!] Invalid Input, Error: {e}")




def validate_pid(pid: int, pid_map: dict[int, str]) -> bool:
    """ Checks if PID exists in previous 'fast-search' dict map """
    
    process_name = pid_map.get(pid)

    if process_name:
        print(f"\n[+] PID found: {pid} ({process_name})")
        return True
    else:
        print(f"[!] Error: PID {pid} not found in snapshot")
        return False


# ---------------------------- Main functions -------------------------------


def get_handle_to_open_process(
    dwDesiredAccess: wintypes.DWORD, 
    bInheritHandle: wintypes.BOOL, 
    dwProcessId: wintypes.DWORD) -> wintypes.HANDLE:

    """ Return handle to open process """

    proc_handle = kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    if not proc_handle:
        raise winerr()   

    print(f"    -> Opened handle to Process: {proc_handle}")
    
    # forcing return of HANDLE/c_void_p
    return wintypes.HANDLE(proc_handle)
    



def open_proc_token(
    ProcessHandle: wintypes.HANDLE,
    DesiredAccess: wintypes.DWORD) -> wintypes.HANDLE:

    """ TokenHandle: a pointer to a handle that identifies newly opened access token """

    token_handle = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(token_handle)):
        raise winerr()

    print(f"    -> Opened handle to Accesstoken: {token_handle.value}")
    return token_handle


# ----------------------------------
#       Context Managers
# ----------------------------------

# to use as 'with x as y'

@contextmanager
def snapshot(flags=TH32CS_SNAPPROCESS):

    print("\n[+] Creating handle to Snapshot: ", end='')
    hSnapshot = wintypes.HANDLE(kernel32.CreateToolhelp32Snapshot(flags, 0))

    if hSnapshot == INVALID_HANDLE_VALUE:
        raise winerr()

    print(f"Successful ({hSnapshot.value})")

    try:
        yield hSnapshot     # give caller, access to handle
    finally:
        close_handle(hSnapshot, "Snapshot")
        hSnapshot.value = 0


# ------------------------------------------
#           Main Execution Block
# ------------------------------------------

# list processes, pids and selection
proc_groups, pid_map = group_pids_by_process()
print_pids_by_process(proc_groups)
chosen_pid = request_pid(pid_map)

# get handles and tokens
proc_handle = get_handle_to_open_process(PROCESS_ALL_ACCESS, False, chosen_pid)
proc_access_token = open_proc_token(proc_handle, TOKEN_ALL_ACCESS)

print("\n[+] Cleaning up: CloseHandle()")
close_handle(proc_handle, "Process", chosen_pid)
close_handle(proc_access_token, "AccessToken")
