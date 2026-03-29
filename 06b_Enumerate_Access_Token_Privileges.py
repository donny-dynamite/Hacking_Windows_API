"""
Enumerate all privileges for a given process' Access Token
- addresses issue with 06_Check_Access_Token_Privileges, where PrivilegeCheck() returns TRUE even if privilege is not listed in access token at all
- accepts user-input to search for specified privilege

Steps:
- PowerShell script to list PIDs, group-by ProcessName
- OpenProcess(), return HANDLE to process
- OpenProcessToken(), return HANDLE to access token
- GetTokenInformation(TokenPrivileges), return access token privileges
- LookupPrivilegeNameW(), map returned LUIDs to human-readable form
"""

import ctypes
from ctypes import wintypes
import subprocess
import sys


kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32.dll', use_last_error=True)


################################
##### PowerShell script(s) #####
################################
#
# - list PIDs, grouped by ProcessName (raw string is okay here)
# - loop for a valid integer to be entered
# - validate entered integer exists as a PID in tasklist/Get-Process

# list PIDs, groupBy ProcessName
script = r'''
Get-Process | Group-Object ProcessName | % {
    [PSCustomObject]@{
        ProcessName = $_.Name
        PIDs = ($_.Group.Id -join ", ")
    }
}
'''

pid_list = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True, text=True)
print(pid_list.stdout)


# loop for valid integer to be entered
while True:
    try:
        pid_value = int(input("\nPlease enter a valid PID: "))
        if pid_value <= 0:
            print("[!] Please enter a positive integer: ")
            continue
        break

    except ValueError as e:
        print(f"\n[!] Invalid Input, Error: {e}")


# validate entered PID
valid_pid = subprocess.run(["powershell", "-NoProfile", "-Command", f"Get-Process -ID {pid_value}"], capture_output=True, text=True)
if not valid_pid.stdout.strip():
    sys.exit(f"[!] PID {pid_value} non-existant. Exiting")




#####################
##### CONSTANTS #####
#####################

SE_PRIVILEGE_ENABLED	    = 0X02  # LUID_AND_ATTRIBUTES()
SE_PRIVILEGE_DISABLED	    = 0X00  # LUID_AND_ATTRIBUTES()




######################################
##### Manually Packed Structures #####
######################################
#
# Following used for looking-up/checking process privs
# - LUID
# -	LUID_AND_ATTRIBUTES
#
# LUID is a 64-bit value, used here to identify privileges
# - two parts associated with lower/higher 32bits (LSB/MSB) of identifier
# - concat to return complete LUID > 0 if valid
#
# ie:
# if (LowPart == 0) and (HighPart == 0):
#     sys.exit(f"[!] Error, LUID not found")

# Note: TOKEN_PRIVILEGES() -> _fields_ = ("Privileges", LUID_AND_ATTRIBUTES * 1)
#
# - this is NOT defining a sub/nested-structure
# - it is defining a variable-length array, with LUID_AND_ATTRIBUTES structs as elements
# - workaround to create array of 1 element, as ctypes does not support variable arrays
# - array of 1-element defined, buffer retrieved, then struct re-cast with proper length
#
# Here, TOKEN_PRIVILEGES_BASE defined without LUID_AND_ATTRIBUTES array, as place holder to retrieve PrivilegeCount
# subsequent TOKEN_PRIVILEGES struct will be defined with correct size
# _fields_ ("Privileges", LUID_AND_ATTRIBUTES * array_length)

class LUID(ctypes.Structure):
	_fields_ = [
	("LowPart",		wintypes.DWORD),
	("HighPart", 	wintypes.LONG)
	]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
	_fields_ = [
	("Luid", 		LUID),
	("Attributes", 	wintypes.DWORD)
	]

# place-holder for variable-length array
class TOKEN_PRIVILEGES_BASE(ctypes.Structure):
    _fields_ = [
    ("PrivilegeCount",  wintypes.DWORD),
    ]




########################################
##### CloseHandle() - kernel32.dll #####
########################################
#
# For clean-up of open handles at the end of execution
# - actual 'HANDLE' objects passed in from OpenProcess() -> return wintypes.HANDLE(ret)
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle#return-value

# func() sigs
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


# wrapper for CloseHandle()
def close_handle(handle, name="Handle"):
    if handle:
        if kernel32.CloseHandle(handle):
            print(f" -> CloseHandle() Successful, {name} Handle: {handle.value}")
        else:
            print(f"[!] CloseHandle() Failed, {name}: {handle.value}, Error: {ctypes.get_last_error()}")




########################################
##### OpenProcess() - kernel32.dll #####
########################################
# 
# Return HANDLE to open process
# - force return type of HANDLE (c_void_p), otherwise ctypes converts to int
#
# This is done for easing Handle cleanup - CloseHandle()
# - ensures consistency when calling CloseHandle() multiple times
# - otherwise proc_handle passed as type 'int', and g_TokenHandle passed as HANDLE object
# - prevents needing to check type()/hasattr()/getattr() when calling CloseHandle()
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights

# func() sigs
kernel32.OpenProcess.argtypes = [
    wintypes.DWORD, # dwDesiredAccess
    wintypes.BOOL,  # bInheritHandle
    wintypes.DWORD  # dwProcessId
]
kernel32.OpenProcess.restype = wintypes.HANDLE

# def params
# PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_ALL_ACCESS = 0x1F0FFF # higher chane of failure if not run elevated, PQLI above as 'safer' alternative
g_dwDesiredAccess = PROCESS_ALL_ACCESS
g_bInheritHandle = False
g_dwProcessId = pid_value


# func() wrapper for OpenProcess()
def open_proc(dwDesiredAccess, bInheritHandle, dwProcessId):
    ret = kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    if not ret:
        raise ctypes.WinError()    
    return wintypes.HANDLE(ret)


try:
    proc_handle = open_proc(g_dwDesiredAccess, g_bInheritHandle, g_dwProcessId)
    print(f"\n[+] OpenProcess() Successful, Process Handle: {proc_handle.value}")

except OSError as e:
    sys.exit(f"\n[!] OpenProcess() Failed. Error: {e}")




#############################################
##### OpenProcessToken() - advapi32.dll #####
#############################################
# 
# return Handle to Access Token ... or rather:
# - update Pointer var (TokenHandle) to contain a HANDLE, which refers to Access Token for given process
#
# Not defining the following:
# - g_ProcessHandle var, as proc_handle exists
# - OpenProcessToken() wrapper as not returning any value, only updating g_TokenHandle in-place
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken#return-value

# func() sigs
advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE,                # ProcessHandle
    wintypes.DWORD,                 # DesiredAccess
    ctypes.POINTER(wintypes.HANDLE) # [o] TokenHandle
    ]
advapi32.OpenProcessToken.restype = wintypes.BOOL

# def params
g_DesiredAccess = 0xF01FF # BitMask for TOKEN_ALL_ACCESS
g_TokenHandle = wintypes.HANDLE()


try:
    if not advapi32.OpenProcessToken(proc_handle, g_DesiredAccess, ctypes.byref(g_TokenHandle)):
        raise ctypes.WinError()
    print(f"[+] OpenProcessToken() Successful, AccessToken Handle: {g_TokenHandle.value}")

except OSError as e:
    sys.exit(f"[!] OpenProcessToken() Failed, Error: {e}")




##################################################
##### LookupPrivilegeValueW() - advapi32.dll #####
##################################################
#
# Retrieve LUID (Locally Unique ID) for a specific privilege name
# - privileges are identified internally by LUIDs (not string names)
# - func() converts human-readable priv into LUID
# - eg from: SeDebugPrivilege -> to: LUID 
#
# NOTE: This func() does NOT check if priv exists in access token
# - only returns if a LUID exists on system, for a given privilege
#
# https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew#return-value

# func() sigs
advapi32.LookupPrivilegeValueW.argtypes = [
	wintypes.LPCWSTR,   			# lpSystemName (can be None)
	wintypes.LPCWSTR,				  # lpName (priv name, eg "SeDebugPrivilege")
	ctypes.POINTER(LUID)	    # [o] lpLuid
]
advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL

# def params
g_lpSystemName = None
g_lpName = input("\nEnter privilege name (eg, SeDebugPrivilege): ") # case-insensitive match performed later
g_lpLuid = LUID()                       # instantiate LUID struct


try:
    if not advapi32.LookupPrivilegeValueW(g_lpSystemName, g_lpName, ctypes.byref(g_lpLuid)):
        raise ctypes.WinError()

    print(f"\n[+] LookupPrivilegeValueW() Sucscessful")
    print(f"Privilege exists on system: {g_lpName}", end=" ")
    print(f"-> LUID High: {g_lpLuid.HighPart}, LUID Low: {g_lpLuid.LowPart}")

except OSError as e:
    sys.exit(f"[!] LookupPrivilegeValueW() Failed, Error: {e}")




#################################################
##### LookupPrivilegeNameW() - advapi32.dll #####
#################################################
#
# Return human-readable name for given LUID
# - pre-defining, will be called in GetTokenInformation()
#
# Two params for name length
# - lpName, pointer to output buffer to receive priv name
#           memory where function writes the string
# - cchName, pointer to DWORD
#            tells Windows how large the buffer (lpName) is
#
# As size of buffer (lpName) is initially unknown, two calls will be made
# - first to retrieve actual buffer size
# - second where both buffer and size of data specified
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegenamew

# func() sigs
advapi32.LookupPrivilegeNameW.argtypes = [
    wintypes.LPCWSTR,               # lpSystemName
    ctypes.POINTER(LUID),           # lpLuid
    wintypes.LPWSTR,                # lpName
    ctypes.POINTER(wintypes.DWORD)  # cchName
]
advapi32.LookupPrivilegeNameW.restype = wintypes.BOOL




#################################################
##### GetTokenInformation () - advapi32.dll #####
#################################################
#
# Third argument passed to func():
# - [out, opt] LPVOID TokenInformation
# - from doco, "The structure put into this buffer, depends upon the TokenInformationClass"
# - struct type is not fixed, can be passed TOKEN_GROUPS, TOKEN_USER, TOKEN_OWNER etc
# - therefore defined as ctypes.c_void_p, not ctypes.POINTER()
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation

# func() sigs
advapi32.GetTokenInformation.argtypes = [
    wintypes.HANDLE,                # TokenHandle
    wintypes.INT,                   # TokenInformationClass
    ctypes.c_void_p,                # [o] TokenInformation (buffer)
    wintypes.DWORD,                 # TokenInformationLength
    ctypes.POINTER(wintypes.DWORD)  # [o] ReturnLength
]
advapi32.GetTokenInformation.restype = wintypes.BOOL

# Specify information to retrieve from access token
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
TokenInformationClass = 3       # TokenPrivileges


###############################################################################
##### NOTE: this whole section will need a re-factor - for now it will do #####
###############################################################################

# call GetTokenInformation() to find required buffer size
size = wintypes.DWORD() 
advapi32.GetTokenInformation(g_TokenHandle, TokenInformationClass, None, 0, ctypes.byref(size))

# allocate buffer size to receive privileges
buf = ctypes.create_string_buffer(size.value) 

# re-call GetTokenInformation() to retrieve privileges
advapi32.GetTokenInformation(g_TokenHandle, TokenInformationClass, buf, size, ctypes.byref(size)) 

token_privs_base = ctypes.cast(buf, ctypes.POINTER(TOKEN_PRIVILEGES_BASE)).contents
array_length = token_privs_base.PrivilegeCount

# re-defining struct with proper array length, then re-casting into proper sized struct
class TOKEN_PRIVILEGES_FULL(ctypes.Structure):
    _fields_ = [
    ("PrivilegeCount",  wintypes.DWORD),
    ("Privileges",      LUID_AND_ATTRIBUTES * array_length)
    ]

token_privs = ctypes.cast(buf, ctypes.POINTER(TOKEN_PRIVILEGES_FULL)).contents
print(f"\n[+] Number of Privileges in Access Token: {token_privs.PrivilegeCount}")

# for matching against user-input privilege
lookup_match = False

# iterate through TOKEN_PRIVILEGES_FULL structure
for i in range(token_privs.PrivilegeCount):
    priv = token_privs.Privileges[i]

    priv_status = 'ENABLED' if (priv.Attributes & SE_PRIVILEGE_ENABLED) else 'DISABLED'
    
    # initial LookupPrivilegeNameW() call -> retrieve proper buffer size
    size = wintypes.DWORD()
    advapi32.LookupPrivilegeNameW(None, ctypes.byref(priv.Luid), None, ctypes.byref(size))
    
    # allocate proper sized buffer
    lpName_buf = ctypes.create_unicode_buffer(size.value)
    cchName_buf = wintypes.DWORD(size.value)
    
    # call LookupPrivilegeNameW() again - to retrieve actual buffer
    priv_name = advapi32.LookupPrivilegeNameW(None, ctypes.byref(priv.Luid), lpName_buf, ctypes.byref(cchName_buf))
    
    if priv_name:
        print(f"{lpName_buf.value}\t\t -> {priv_status}\tLUID: ({priv.Luid.HighPart}, {priv.Luid.LowPart})")
        
        # case-insensitive match, for user-input privilege
        if lpName_buf.value.lower() == g_lpName.lower():
            lookup_match = True
        
    else:
        print(f"[!] LookupPrivilegeNameW() Failed, LUID: ({priv.Luid.HighPart}, {priv.Luid.LowPart})")


# check if user-entered privilege, exists in access token
if lookup_match:
    print(f"\n[+] Privilege match found in Access Token: {g_lpName}")
else:
    print(f"\n[!] Privilige match NOT found: {g_lpName}")
