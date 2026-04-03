"""
Terminate process for a given window title
------------------------------------------

CreateToolhelp32Snapshot()
- system snapshot, enumeration via Process32FirstW() -> Process32NextW()

The barebones script uses FindWindowW(), as window-title is known/given
- here, *all* window-titles are returned for a given process name (eg, notepad.exe)
- and where process name has multiple instances/PIDs, all are processed
- as such, EnumWindows() is utilised

EnumWindows() <- EnumWindowsProc()
- iterate all top-level windows, call-back function for processing each window

Note: potential overwrite where a single PID has multiple titles, only last recorded 
"""


import ctypes
from ctypes import wintypes
from collections import defaultdict
from contextlib import contextmanager
import msvcrt


kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)
user32 = ctypes.WinDLL('user32.dll', use_last_error=True)


# ----------------------------------
# CONSTANTS
# ----------------------------------

# kernel32.CreateToolhelp32Snapshot()
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1)
TH32CS_SNAPPROCESS = 0x02

# PROCESSENTRY32W() struct
MAX_PATH = 260

# OpenProcess()
PROCESS_ALL_ACCESS = 0x1F0FFF  # likely to fail unless run elevated/as-admin
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000  # alternative, minimal privs required


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
# Callback Types
#----------------------------------

# call-back function passed to EnumWindows()
EnumWindowsProc  = ctypes.WINFUNCTYPE(
    wintypes.BOOL,      # return type
    wintypes.HWND,      # hWnd, handle to a top-level window
    wintypes.LPARAM     # lParam, app-defined value given in EnumWindows()
)


# ----------------------------------
# Function Signatures
# ----------------------------------

# ----- kernel32 -----
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

kernel32.TerminateProcess.argtypes = [
    wintypes.HANDLE,    # hProcess
    wintypes.UINT       # uExitCode
]
kernel32.TerminateProcess.restype = wintypes.BOOL

# ----- user32 -----
user32.EnumWindows.argtypes = [
    EnumWindowsProc,    # lpEnumFunc, pointer to call-back function (defined above)
    wintypes.LPARAM,    # lParam, app-defined valued passed to call-back func
]
user32.EnumWindows.restype = wintypes.BOOL

user32.GetWindowThreadProcessId.argtypes =[
    wintypes.HWND,      # hWnd
    wintypes.LPDWORD    # [o] lpdwProcessId (opt)
]
user32.GetWindowThreadProcessId.restype  = wintypes.DWORD

user32.GetWindowTextLengthW.argtypes = [
    wintypes.HWND,      # hWnd, handle to window
]
user32.GetWindowTextLengthW.restype = wintypes.INT

user32.GetWindowTextW.argtypes = [
    wintypes.HWND,      # hWnd, window to handle (or control) containing text
    wintypes.LPWSTR,    # [o] lpString, buffer to receive string
    wintypes.INT,       # nMaxCount, max chars to copy to buffer (including null)
]
user32.GetWindowTextW.restype = wintypes.INT

user32.IsWindowVisible.argtypes = [
    wintypes.HWND,       # hWnd, handle to window
]
user32.IsWindowVisible.restype = wintypes.BOOL



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
            dict[str, list[int]]
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
    
    [+] proc_lookup: O(1)
    - reference-dict, stored as names.lower() to handle case-ness of filenames
    - keys point to same list-object (value) in proc_groups
    """

    # proc_groups -> for iterating whole list in full print-out
    proc_groups: defaultdict[str, list[int]] = defaultdict(list)

    # pre-define dicts for quicker O(1) searches, v O(n)
    # - pid_proc_map -> PID validation
    # - proc_lookup -> process validation
    # pid_to_proc_map: dict[int, str] = {}
    proc_lookup: dict[str, list[int]] ={}

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
            # rapid look-up dicts{}
            # pid_to_proc_map[pid] = name
            proc_lookup[name.lower()] = proc_groups[name]
            
                
            if not kernel32.Process32NextW(hSnapshot, ctypes.byref(pe32w)):
                break

        print("Completed")

    return proc_groups, proc_lookup




def key_sort(name: str) -> str:
    """ Ensure processes sorted alphabetically, regardless of case """
    #return re.sub(r'[^a-z0-9]', '', name.lower())
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





def request_process(proc_lookup: dict[str, list[int]]) -> list[int]:
    """
    Request/validate process name, returning associated PIPDs
    """
    
    print('\n' + '-' * 87)
    while True:
        proc_name = input("Enter process name: ").strip().lower()

        # checking proc_lookup due to case-ness of process names
        pid_list = proc_lookup.get(proc_name)
        if not pid_list:
            print(f"\n[!] Error, Process '{proc_name}' not found")
        else:
            print(f"\n[+] Found PIDs: {pid_list}")
            return pid_list




def get_window_titles(pid_list: list[int]) -> dict[int, str]:
    pid_title_map: dict[int, str] = {}

    # decorator that wraps func -> converts to C func pointer that can be called
    @EnumWindowsProc
    def callback(hWnd, lParam):
        """
        CallBack function for user32.EnumWindows()
        
        Function iterates through every single top-level window on system...
        - passing-in handle to callback function
        
        Callback function performs following operations:
        - check window-PID, matches given process-PID
        - check if window 'logically visible'
        - retrieves the window title, appending it to a list

        Return True - continue enumeration
        - ie, move onto next window in sequence
        - similar to 'continue' within a loop
        
        Return False - stop enumeration
        - similar to 'break' within a loop
        
        user32.IsWindowVisible()
        - some processes will have a single PID, but multiple possible titles
        - eg notepad++.exe, where each tab will change the Window Title contents
        - this function will only return the 'visible' window/tab, not any others
        """

        # get PID for window, and check if in pid_list
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hWnd, ctypes.byref(pid))
        
        if pid.value not in pid_list:
            return True

        # check if 'logically visible'
        if not user32.IsWindowVisible(hWnd):
            return True


        # get window title
        size = user32.GetWindowTextLengthW(hWnd)
        if size == 0:
            return True
        
        buf = ctypes.create_unicode_buffer(size + 1)
        user32.GetWindowTextW(hWnd, buf, size + 1)

        title = buf.value.strip()
        if title:
            pid_title_map[pid.value] = title    # store PID and title in dict

        # end of checks for current window title
        return True
    
    user32.EnumWindows(callback, 0)
    return pid_title_map




def request_window_title(pid_title_map: dict[int, str]) -> int:
    """
    Print list of titles, and associated index
    - request user to select title, given index
    - return PID for selected window title    
    """

    # header info
    print("\nAvailable Window Titles:\n" + "-" * 36)

    # print available window titles
    for i, (pid, title) in enumerate(pid_title_map.items()):
        print(f"[{i}]: Title, {title:<30} (pid: {pid})")

    length = len(pid_title_map)

    while True:
        try:
            selection = int(input("\nSelect number for window title: "))

            if 0 <= selection < length:
                # convert dict -> list, to access key/PID by index
                title_choice = list(pid_title_map.keys())[selection]
                return title_choice

            else:
                print(f"[!] Please enter a number between 0 and {length -1}.")

        except ValueError:
            print("[!] Invalid input. Please enter a number from above.")




'''
Note: these functions are not required for this script
- kept for posterity

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
'''


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
# <- proc_lookup: dict[str, list[int]]

proc_groups, proc_lookup = group_pids_by_process()
pause()


# ----------------------------------
# Manage selection of Process Name
# ----------------------------------

# print pids, grouped by process name 
print_pids_by_process(proc_groups)

# User-Input -> request process name <- return associated PIDs
pid_list = request_process(proc_lookup)


# ----------------------------------
# Manage selection of Window Title
# ----------------------------------

# return dict of pid/title k,v pairs
pid_title_map = get_window_titles(pid_list)

# User-Input -> select window title <- return pid for window title
pid_for_window_title = request_window_title(pid_title_map)


# ----------------------------------
# Open handle to process
# ----------------------------------

with open_process(pid_for_window_title) as pHandle:
    # print("\n--> Do Stuff Here...")
    
    # terminate process
    print(f"\n[!] Terminating Process Id: {pid_for_window_title}")
    kernel32.TerminateProcess(pHandle,0)
