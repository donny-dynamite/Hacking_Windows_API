"""
Open a handle to an existing process
- PID selection / validation via python standard libraries

CreateToolhelp32Snapshot()
- 'snapshot' taken of running system processes
- subsequent process enumeration, Process32FirstW() -> Process32NextW()
"""

import ctypes
from ctypes import wintypes
from collections import defaultdict
from contextlib import contextmanager


kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)


#####################
##### CONSTANTS #####
#####################

# kernel32.CreateToolhelp32Snapshot()
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1)
TH32CS_SNAPPROCESS = 0x02

# PROCESSENTRY32W() struct
MAX_PATH = 260

# OpenProcess()
PROCESS_ALL_ACCESS = 0x1F0FFF               # likely to fail unless run elevated/as-admin
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000  # alternative, minimal privileges required




##############################
##### Struct Definitions #####
##############################

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




###############################
##### Function Signatures #####
###############################
#
# ensure correct data-type of passed arguments, and return types

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




################################
##### Function definitions #####
################################

def winerr():
    """Return a ctypes.WinError() with the last Windows API error."""
    return ctypes.WinError(ctypes.get_last_error())




def close_handle(handle, name="Handle"):
    """
    Close open handles and set variable to None, to prevent dangling pointers
    """

    print(f"\nClosing Handle to {name}...")
    if not handle:
        raise ValueError(f"[!] Warning: {name} is None or invalid, nothing to close")

    if not kernel32.CloseHandle(handle):
        print(f"\n[!] CloseHandle() Failed, {name}: {handle}, Error: {winerr()}")
    else:
        print(f"[+] CloseHandle() Successful, {name} Handle: {handle.value}")

    return None



def group_pids_by_process():
    """
    Returns defaultdict() of process names, and list of associated PIDs
    - snapshot taken of running processes - TH32CS_SNAPPROCESS
    - iterated by Process32FirstW -> Process32NextW, until empty
    """

    # - proc_groups -> for iterating whole list in full print-out
    # - pid_proc_map -> fast search for later-on PID validation
    proc_groups = defaultdict(list)
    pid_to_proc_map = {}

    pe32w = PROCESSENTRY32W()
    pe32w.dwSize = ctypes.sizeof(PROCESSENTRY32W)

    # Context Manager - snapshot
    with snapshot(TH32CS_SNAPPROCESS) as hSnapshot: 
        if not kernel32.Process32FirstW(hSnapshot, ctypes.byref(pe32w)):
            raise winerr()

        while True:
            name = pe32w.szExeFile      # process name
            pid  = pe32w.th32ProcessID  # leave PIDs as ints in list

            proc_groups[name].append(pid)
            pid_to_proc_map[pid] = name

            if not kernel32.Process32NextW(hSnapshot, ctypes.byref(pe32w)):
                break

    return proc_groups, pid_to_proc_map




def print_pids_by_process(process_groups):
    """
    Print Process Names -> associated PIDs -> count of PIDs
    - sorted alphabetically, then numerically
    - PID list truncated if too long (eg svchost.exe)
    """

    # header info
    print(f"{'Process Name':<40} {'PID':<40} {'Count':>5}")
    print('-' * 87)


    for process_name in sorted(process_groups.keys()):
        sorted_pids = sorted(process_groups[process_name])
        
        # join pids -> must first be converted to type str()
        pid_list_str = ', '.join(str(pid) for pid in sorted_pids)
        
        count = len(sorted_pids)
        
        # truncate long list of PIDs
        if len(pid_list_str) > 35:
            pid_list_str = pid_list_str[:35] + '...'
        
        print(f"{process_name:<40} {pid_list_str:<40} {count:<5}")




def request_pid(pid_map):
    """
    Return positive integer -> later validate if actual PID
    """

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




def validate_pid(pid, pid_map):
    """
    Checks PID exists in previous 'fast-search' dictionary map
    """

    process_name = pid_map.get(pid)
                
    if process_name:
        print(f"[+] PID found: {pid}, Process: {process_name}")
        return True
    else:
        print(f"[!] Error: PID {pid} not found in snapshot")
        return False




############################
##### Context Managers #####
############################
#
# To be able to use 'with x as y:'
# - automatically closes handles upon exit

@contextmanager
def open_process(dwProcessId, dwDesiredAccess=PROCESS_ALL_ACCESS, bInheritHandle=False):
    handle = wintypes.HANDLE(kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId))

    if not handle:
        raise winerr()

    try:
        yield handle        # give caller, access to handle
    finally:
        handle = close_handle(handle, "Process")




@contextmanager
def snapshot(flags=TH32CS_SNAPPROCESS):
    hSnapshot = wintypes.HANDLE(kernel32.CreateToolhelp32Snapshot(flags, 0))
    
    if hSnapshot == INVALID_HANDLE_VALUE:
        raise winerr()

    try:
        yield hSnapshot     # give caller, access to handle
    finally:
        hSnapshot = close_handle(hSnapshot, "Snapshot")




###############################################
##### Process ID selection and validation #####
###############################################

# retrieve process snapshot -> for printing and pid validation
proc_groups, pid_map = group_pids_by_process()

# print pids, grouped by process name 
print_pids_by_process(proc_groups)

# ask/validate user entered PID -> returns int
chosen_pid = request_pid(pid_map)





#########################################################
##### Create handle to open process - OpenProcess() #####
#########################################################

with open_process(chosen_pid) as pHandle:
    print(f"\n[+] OpenProcess() Successful, Process Handle: {pHandle.value}")
