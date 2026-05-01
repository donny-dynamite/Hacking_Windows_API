"""
(barebones) Enumerate Privileges of an Access Token


Steps:
------
- Choose PID
- OpenProcess()             -> get handle to process
- OpenProcessToken()        -> get handle to access token
- GetTokenInformation()     -> return all privileges listed access token
- LookupPrivilegeNameW()    -> iterate and print

"""

import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32.dll', use_last_error=True)

# --------------- Struct Definitions ---------------

class LUID(ctypes.Structure):
	_fields_ = [
	("LowPart",		wintypes.DWORD),
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

# --------------- Function Prototypes ---------------

kernel32.CloseHandle.argtypes = [wintypes.HANDLE,]  # hObject
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,         # dwDesiredAccess
    wintypes.BOOL,          # bInheritHandle
    wintypes.DWORD,         # dwProcessId
]
kernel32.OpenProcess.restype = wintypes.HANDLE

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

# --------------- Main Execution Block ---------------

# USER-INPUT: enter PID
chosen_pid = int(input("Enter PID: "))

# handle to process
proc_handle = wintypes.HANDLE(kernel32.OpenProcess(0x1F0FFF, False, chosen_pid))

# handle to access token
token_handle = wintypes.HANDLE()
advapi32.OpenProcessToken(proc_handle, 0xF01FF, ctypes.byref(token_handle))


# ----- process AccessToken Information -----
"""
    memory layout of buffer:
    ------------------------
    [DWORD PrivilegeCount]      <- 'array_length' reads in this value
    [LUID_AND_ATTRIBUTES #1]
    [LUID_AND_ATTRIBUTES #2]
    [LUID_AND_ATTRIBUTES #n]
"""

# double-call -> populate buffer
size = wintypes.DWORD(0)
advapi32.GetTokenInformation(token_handle, 3, None, 0, ctypes.byref(size))

buffer = ctypes.create_string_buffer(size.value)
advapi32.GetTokenInformation(token_handle, 3, buffer, size.value, ctypes.byref(size))


# cast buffer to TP struct
array_length = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value 

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount",  wintypes.DWORD),
        ("Privileges",      LUID_AND_ATTRIBUTES * array_length)
    ]

token_privileges = ctypes.cast(buffer, ctypes.POINTER(TOKEN_PRIVILEGES)).contents


# ----- iterate through LUID_AND_ATTRIBUTES() structs in buffer -----
print(f"\n[+] Enumerating Privileges in Access Token:")
for i in range(token_privileges.PrivilegeCount):

    privilege = token_privileges.Privileges[i]
    privilege_status = 'Enabled' if (privilege.Attributes & 0X02) else 'Disabled'

    # double-call -> populate buffer for privilege name
    size_name = wintypes.DWORD()
    advapi32.LookupPrivilegeNameW(None, ctypes.byref(privilege.Luid), None, ctypes.byref(size_name))

    privilege_name = ctypes.create_unicode_buffer(size_name.value)
    advapi32.LookupPrivilegeNameW(None, ctypes.byref(privilege.Luid), privilege_name, ctypes.byref(size_name))

    # print privilege information, name / status (enabled/disabled), LUID
    print(f" {i} -> {privilege_name.value:<30}  {privilege_status:<10} LUID: ({privilege.Luid.HighPart}, {privilege.Luid.LowPart})")


# Clean-up
kernel32.CloseHandle(proc_handle)
kernel32.CloseHandle(token_handle)
