"""
(prod) Enumerate Privileges of an Access Token


Steps:
------
- Choose PID from list (grouped by ProcessName)
- OpenProcess()             -> get handle to process
- OpenProcessToken()        -> get handle to access token
- GetTokenInformation()     -> return all privileges listed access token
- LookupPrivilegeNameW()    -> iterate and print


Note:
-----
- not utilising PrivilegeCheck() here
- as it does not differentiate between exist_but_disabled vs does_not_exist

"""

import ctypes
from ctypes import wintypes
from collections import defaultdict
from contextlib import contextmanager
import sys

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

# GetTokenInformation()
TokenPrivileges             = 3

# OpenProcess()
PROCESS_ALL_ACCESS  = 0x1F0FFF

# OpenProcessToken()
TOKEN_ALL_ACCESS    = 0xF01FF

# PROCESSENTRY32W() struct
MAX_PATH = 260

# Privileges and LUIDs
PRIVILEGE_SET_ALL_NECESSARY = 0x01  # PRIVILEGE_SET()
SE_PRIVILEGE_ENABLED	    = 0X02  # LUID_AND_ATTRIBUTES()
SE_PRIVILEGE_DISABLED	    = 0X00  # LUID_AND_ATTRIBUTES()


# ---------------------------------------------------
#               Struct Definitions
# ---------------------------------------------------

class LUID(ctypes.Structure):           # LUID is a 64-bit value, used here to identify privileges
	_fields_ = [                        # - two parts refer to lower/higher 32-bits of id (LSB/MSB)
	("LowPart",		wintypes.DWORD),    # - reason for DWORD v LONG is historical
	("HighPart", 	wintypes.LONG),
	]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
	_fields_ = [
	("Luid", 		LUID),
	("Attributes", 	wintypes.DWORD),
	]

class PRIVILEGE_SET(ctypes.Structure):
	_fields_ = [
	("PrivilegeCount",	wintypes.DWORD),
	("Control", 		wintypes.DWORD),
	("Privilege", 		LUID_AND_ATTRIBUTES),
	]

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

array_length = 0 # place_holder that will be replaced later
class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount",  wintypes.DWORD),
        ("Privileges",      LUID_AND_ATTRIBUTES * array_length)
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

advapi32.GetTokenInformation.argtypes = [
    wintypes.HANDLE,                # TokenHandle
    wintypes.INT,                   # TokenInformationClass
    ctypes.c_void_p,                # [o] TokenInformation (opt)
    wintypes.DWORD,                 # TokenInformationLength
    ctypes.POINTER(wintypes.DWORD)  # [o] ReturnLength
]
advapi32.GetTokenInformation.restype = wintypes.BOOL

advapi32.LookupPrivilegeNameW.argtypes = [
    wintypes.LPCWSTR,               # lpSystemName (opt, None)
    ctypes.POINTER(LUID),           # lpLuid
    wintypes.LPWSTR,                # [o] lpName (opt)
    ctypes.POINTER(wintypes.DWORD)  # [i/o] cchName, size/length of lpName (!including null-terminator)
]
advapi32.LookupPrivilegeNameW.restype = wintypes.BOOL

advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE,                    # ProcessHandle
    wintypes.DWORD,                     # DesiredAccess
    ctypes.POINTER(wintypes.HANDLE),    # [o] TokenHandle
    ]
advapi32.OpenProcessToken.restype = wintypes.BOOL

advapi32.PrivilegeCheck.argtypes = [
	wintypes.HANDLE,							# ClientToken, handle to AccessToken
	ctypes.POINTER(PRIVILEGE_SET),	            # [i/o] RequiredPrivileges, pointer to PRIVILEGE_SET()
	ctypes.POINTER(wintypes.BOOL),				# [o] pfResult, whether any/all priv(s) are enabled in AccessToken
]
advapi32.PrivilegeCheck.restype = wintypes.BOOL


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


def group_pids_by_process() -> tuple[
        defaultdict[str, list[int]],
        dict[int, str]
        ]:

    """
    Snapshot taken of running processes -> TH32CS_SNAPPROCESS
    - iterated by Process32FirstW() -> Process32NextW() until empty

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
    print(f"\n{'Process Name':<40} {'PID':<40} {'Count':>5}\n" + '-' * 87)

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
    
    # forcing return of HANDLE/c_void_p - for some reason insists on returning an 'int' type
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




def enumerate_token_privileges(
        token_handle: wintypes.HANDLE,
        TokenInformationClass: int,
        priv_name: str) -> None:

    """
    Enumerate through privileges in AccessToken
    
    (from docs) When passing "TokenPrivileges" (3) as TokenInformationClass, the buffer receives a TOKEN_PRIVILEGES() struct
 
    for 'array_length', we cast the buffer against a pointer that reads the PrivilegeCount field
    - ie, assign the first 4-bytes (DWORD) of the buffer, to the variable 'array_length'
    - variable required for when casting the buffer to a TOKEN_PRIVILEGES() struct

    memory layout of buffer:
    ------------------------
    [DWORD PrivilegeCount]      <- 'array_length' reads in this value
    [LUID_AND_ATTRIBUTES #1]
    [LUID_AND_ATTRIBUTES #2]
    [LUID_AND_ATTRIBUTES #n]

    """

    # double-call probe to find correct size for buffer
    size = wintypes.DWORD()
    advapi32.GetTokenInformation(token_handle, TokenInformationClass, None, 0, ctypes.byref(size))

    # second call
    buffer = ctypes.create_string_buffer(size.value)
    if not advapi32.GetTokenInformation(token_handle, TokenInformationClass, buffer, size.value, ctypes.byref(size)):
        raise winerr()

    # read 'PrivilegeCount' field in buffer
    array_length = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value 

    # struct defined here due to requiring specific length of array
    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [
            ("PrivilegeCount",  wintypes.DWORD),
            ("Privileges",      LUID_AND_ATTRIBUTES * array_length)
        ]

    # ----- cast buffer into new struct instance -----
    token_privileges = ctypes.cast(buffer, ctypes.POINTER(TOKEN_PRIVILEGES)).contents

    # to see if chosen privilege in list
    lookup_match = 0
    
    # ----- iterate through LUID_AND_ATTRIBUTES() structs in buffer -----
    print(f"\n[+] Enumerating Privileges in Access Token:")
    for i in range(token_privileges.PrivilegeCount):
        
        privilege = token_privileges.Privileges[i]
        privilege_status = 'Enabled' if (privilege.Attributes & SE_PRIVILEGE_ENABLED) else 'Disabled'
        
        # double-call - probe
        size_name = wintypes.DWORD()
        advapi32.LookupPrivilegeNameW(None, ctypes.byref(privilege.Luid), None, ctypes.byref(size_name))
     
        # second call
        privilege_name = ctypes.create_unicode_buffer(size_name.value)
        
        if not advapi32.LookupPrivilegeNameW(None, ctypes.byref(privilege.Luid), privilege_name, ctypes.byref(size_name)):
            print(f"[!] LookupPrivilegeNameW() Failed, LUID: ({privilege.Luid.HighPart}, {privilege.Luid.LowPart})")
            continue
        else:
            print(f" {i} -> {privilege_name.value:<30}  {privilege_status:<10} LUID: ({privilege.Luid.HighPart}, {privilege.Luid.LowPart})")

            # increment if privilege exists in access token, as for-loop will reset on each iteration if True/False
            lookup_match += int(privilege_name.value.lower() == priv_name.lower())


    # check if our chosen privilege, exists in the token
    status = 'True' if lookup_match else 'False'
    print(f"\nIs privilege '{priv_name}' included in AccessToken: {status}")




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
handle_to_access_token = open_proc_token(proc_handle, TOKEN_ALL_ACCESS)


# check if priv exists in access token
priv_name = input("\nEnter privilege name (eg, SeDebugPrivilege): ")        # case-insensitive match performed
enumerate_token_privileges(handle_to_access_token, TokenPrivileges, priv_name)


print("\n[+] Cleaning up: CloseHandle()")
close_handle(proc_handle, "Process", chosen_pid)
close_handle(handle_to_access_token, "AccessToken")
