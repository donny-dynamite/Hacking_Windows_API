"""
Open a handle to an existing process
-------------------------------------

Process listing/selection/validation via CreateToolhelp32Snapshot()
- 'snapshot' taken, listing running processes on host
- subsequent enumeration via Process32FirstW() -> Process32NextW()
"""

import ctypes
from ctypes import wintypes
from collections import defaultdict
from contextlib import contextmanager
import msvcrt


kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)


# ----------------------------------
# CONSTANTS
# ----------------------------------

# kernel32.CreateToolhelp32Snapshot()
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1)
TH32CS_SNAPPROCESS = 0x02

# PROCESSENTRY32W() struct
MAX_PATH = 260

# OpenProcess()
PROCESS_ALL_ACCESS = 0x1F0FFF               # likely to fail unless run elevated/as-admin
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000  # alternative, minimal privileges required




# ----------------------------------
# Struct Definitions
# ----------------------------------


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




# ----------------------------------
# Function Signatures
# ----------------------------------

kernel32.CloseHandle.argtypes = [ wintypes.HANDLE, ]  # hObject
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.CreateToolhelp32Snapshot.argtypes=[
    wintypes.DWORD,     # dwFlags
    wintypes.DWORD,     # th32ProcessID
]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,    # dwDesiredAccess
    wintypes.BOOL,     # bInheritHandle
    wintypes.DWORD,    # dwProcessId
]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.Process32FirstW.argtypes = [
    wintypes.HANDLE,                    # hSnapshot
    ctypes.POINTER(PROCESSENTRY32W),    # [o] lppe, proc-list entry from snapshot
]
kernel32.Process32FirstW.restype = wintypes.BOOL

kernel32.Process32NextW.argtypes=[
    wintypes.HANDLE,                    # hSnapshot
    ctypes.POINTER(PROCESSENTRY32W),    # [o] lppe, proc-list entry from snapshot
]
kernel32.Process32NextW.restype = wintypes.BOOL




# ----------------------------------
# Function Definitions
# ----------------------------------

def winerr() -> OSError:
    """ Return a ctypes.WinError() with the last Windows API error """
    return ctypes.WinError(ctypes.get_last_error())




def close_handle(handle: wintypes.HANDLE, name: str="Handle") -> None:
    """ Close open handles, to prevent dangling pointers """

    print(f"\n[+] Closing Handle to {name}... ", end='', flush=True)
    if handle is None or handle.value == 0:
        raise ValueError(f"[!] Warning: {name} is None or invalid, nothing to close")

    if not kernel32.CloseHandle(handle):
        print(f"Failed! {name} handle: {handle}, Error: {winerr()}")
    else:
        print(f"Successful -> {name} handle: {handle.value}")




def group_pids_by_process() -> tuple[
            defaultdict[str, list[int]],
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

        print("--> Taking Snapshot of running processes... ", end='', flush=True)

        while True:
            name = pe32w.szExeFile      # process name
            pid  = pe32w.th32ProcessID  # leave PIDs as ints in list

            proc_groups[name].append(pid)
            pid_to_proc_map[pid] = name
                
            if not kernel32.Process32NextW(hSnapshot, ctypes.byref(pe32w)):
                break

        print("Completed")

    return proc_groups, pid_to_proc_map




def key_sort(name: str) -> str:
    """ Ensure processes sorted alphabetically, regardless of case """
    return name.casefold()




def pause() -> None:
    """ Pause until user key press (any) """
    msg = "\nPress any key to continue (list PIDs by process) ..."
    print(msg, end='', flush=True)
    msvcrt.getch()
    print()




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
        print(f"[+] PID found: {pid}, Process: {process_name}")
        return True
    else:
        print(f"[!] Error: PID {pid} not found in snapshot")
        return False




# ----------------------------------
# Context Managers
# ----------------------------------
#
# To be able to use 'with x as y:'
# - to automatically close handles upon exit

@contextmanager
def open_process(dwProcessId, dwDesiredAccess=PROCESS_ALL_ACCESS, bInheritHandle=False):
    print(f"\n[+] Opening Handle to process... ", end='', flush=True)

    handle = wintypes.HANDLE(kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId))

    if not handle:
        raise winerr()

    print(f" Successful -> Process handle: {handle.value}")

    try:
        yield handle        # give caller, access to handle
    finally:
        close_handle(handle, "Process")
        handle.value = 0




@contextmanager
def snapshot(flags=TH32CS_SNAPPROCESS):
    print("\n[+] Creating handle to Snapshot... ", end='', flush=True)
    hSnapshot = wintypes.HANDLE(kernel32.CreateToolhelp32Snapshot(flags, 0))

    if hSnapshot == INVALID_HANDLE_VALUE:
        raise winerr()

    print(f"Successful -> Snapshot handle: {hSnapshot.value}")

    try:
        yield hSnapshot     # give caller, access to handle
    finally:
        close_handle(hSnapshot, "Snapshot")
        hSnapshot.value = 0




##########################################
##### Main functionality starts here #####
##########################################

# ----------------------------------
# Process system snapshot
# ----------------------------------

# <- proc_groups: defaultdict[str, list[int]]
# <- pid_map: dict[int, str]

proc_groups, pid_map = group_pids_by_process()
pause()

# ----------------------------------
# Manage selection of Process Id
# ----------------------------------

# Print pids, grouped by process name 
print_pids_by_process(proc_groups)

# Ask/validate user entered PID <- returns int
chosen_pid = request_pid(pid_map)


# ----------------------------------
# Open handle to process
# ----------------------------------

with open_process(chosen_pid) as pHandle:
    print("\n--> Do Stuff Here...")
