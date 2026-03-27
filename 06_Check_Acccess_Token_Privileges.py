"""
Check to see if Access Token for a given process, contains a specific privilege
- additionally, whether it is ENABLED or DISABLED

CAVEAT: PrivilegeCheck() does NOT distinguish between priv that is missing, or present+disabled

Steps:
- PowerShell script to list PIDs, group-by ProcessName
- OpenProcess() for given PID
- OpenProcessToken() for returned process handle
- LookupPrivilegeValueW() to retrieve LUID for specific privilege
- PrivilegeCheck() to see if LUID/priv a/w process, and if ENABLED/DISABLED
"""

import ctypes
from ctypes import wintypes
import subprocess
import sys

# import DLLs
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
        pid_value = int(input("\nEnter a single PID from above list: "))
        if pid_value > 0:
            break
        else:
            print(f"\nPlease enter single PID from above list")
    except ValueError as e:
        print(f"\n[!] Invalid Input, Error: {e}")

# validate entered PID
valid_pid = subprocess.run(["powershell", "-NoProfile", "-Command", f"Get-Process -ID {pid_value}"],
                            capture_output=True, text=True)

if not valid_pid.stdout.strip():
    sys.exit(f"[!] PID {pid_value} non-existant. Exiting")




######################################
##### Manually Packed Structures #####
######################################
#
# Following used for looking-up/checking process privs
# - LUID
# -	LUID_AND_ATTRIBUTES
# - PRIVILEGE_SET
#
# LUID is a 64-bit value, used here to identify privileges
# - two parts associated with lower/higher 32bits (LSB/MSB) of identifier
# - combined together to return complete LUID
# - returns > 0 if valid
#
# ie:
# if (LowPart == 0) and (HighPart == 0):
#     sys.exit(f"[!] Error, LUID not found")

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

class PRIVILEGE_SET(ctypes.Structure):
	_fields_ = [
	("PrivilegeCount",	wintypes.DWORD),
	("Control", 		wintypes.DWORD),
	("Privilege", 		LUID_AND_ATTRIBUTES)
	]



########################################
##### OpenProcess() - kernel32.dll #####
########################################
# 
# Return HANDLE to open process
# - force return type of HANDLE, because otherwise ctypes converts to int
#
# This is done for easing Handle cleanup - CloseHandle()
# - ensures consistency when calling CloseHandle() multiple times
# - otherwise proc_handle passed as type 'int', and g_TokenHandle passed as HANDLE object
# - prevents needing to check type()/hasattr()/getattr() when calling CloseHandle()
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights

# func() sigs
kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD
]
kernel32.OpenProcess.restype = wintypes.HANDLE

# def params
# PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_ALL_ACCESS = 0x1F0FFF # BitMask value
g_dwDesiredAccess = PROCESS_ALL_ACCESS
g_bInheritHandle = False
g_dwProcessId = pid_value


# func() wrapper for OpenProcess()
def open_proc(dwDesiredAccess, bInheritHandle, dwProcessId):
    ret = kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)

    if not ret:
        raise ctypes.WinError()    

    # forcing HANDLE return type
    return wintypes.HANDLE(ret)


try:
    proc_handle = open_proc(g_dwDesiredAccess, g_bInheritHandle, g_dwProcessId)
    print(f"\n[+] OpenProcess() Successful, Process Handle: {proc_handle.value}")

except OSError as e:
    sys.exit(f"\n[!] OpenProcess() Failed. Error: {e}")




########################################
##### CloseHandle() - kernel32.dll #####
########################################
#
# For cleaning up handles at the very end
# - actual HANDLE objects passed
# - due to 'return wintypes.HANDLE(ret)' in OpenProcess() above
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle#return-value

# func() sigs
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


# func() wrapper for CloseHandle()
def close_handle(handle, name="Handle"):
    if handle:
        if kernel32.CloseHandle(handle):
            print(f"[+] CloseHandle() Successful, {name} Handle: {handle.value}")
            return None
            
        else:
            print(f"[!] CloseHandle() Failed, {name}: {handle.value}, Error: {kernel32.GetLastError()}")
            return handle




#############################################
##### OpenProcessToken() - advapi32.dll #####
#############################################
# 
# return Handle to Access Token ... or rather:
# - update Pointer var (TokenHandle) to contain HANDLE
# - that refers to Access Token for given process
#
# g_ProcessHandle param not defined, as proc_handle exists
# 
# open_proc_token() wrapper refactored as such
# - no need to define-param or pass-arg ProcessHandle, handled in internal OpenProcessToken() call
# - no type returned, only called to update g_TokenHandle in place
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken#return-value

# func() sigs
advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.HANDLE)
    ]
advapi32.OpenProcessToken.restype = wintypes.BOOL

# def params
g_DesiredAccess = 0xF01FF # BitMask for TOKEN_ALL_ACCESS
g_TokenHandle = wintypes.HANDLE()


# func() wrapper for OpenProcessToken()
def open_proc_token(DesiredAccess, TokenHandle):
    if not advapi32.OpenProcessToken(proc_handle, DesiredAccess, ctypes.byref(TokenHandle)):
        raise ctypes.WinError()


try:
    open_proc_token(g_DesiredAccess, g_TokenHandle)
    print(f"[+] OpenProcessToken() Successful, AccessToken Handle: {g_TokenHandle.value}")

except OSError as e:
    sys.exit(f"[!] OpenProcessToken() Failed, Error: {e}")




##################################################
##### LookupPrivilegeValueW() - advapi32.dll #####
##################################################
#
# Retrieve LUID (Locally Unique ID) for a specific privilege name
# - privileges are id' internally by LUIDs (not string names)
# - func() converts human-readable priv into LUID
# - eg from: SeDebugPrivilege -> to: LUID 
#
# Then included in struct(), which is passed to PrivilegeCheck()
#
# https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew#return-value

# func() sig
advapi32.LookupPrivilegeValueW.argtypes = [
	wintypes.LPCWSTR,   			# lpSystemName (can be None)
	wintypes.LPCWSTR,				# lpName (priv name, eg "SeDebugPrivilege")
	ctypes.POINTER(LUID)	        # lpLuid (output)
]
advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL

# def params
g_lpSystemName = None
g_lpName = "SeCreatePagefilePrivilege"	# case-insensitive, but casing for consistency
g_lpLuid = LUID()               # instantiate LUID struct


# func() wrapper
def retr_luid(lpSystemName, lpName, lpLuid):
    # non-zero return on success
    ret = advapi32.LookupPrivilegeValueW(lpSystemName, lpName, ctypes.byref(lpLuid))
    return ret

try:
    if retr_luid(g_lpSystemName, g_lpName, g_lpLuid) == 0:
        sys.exit(f"[!] LookupPrivilegeValueW() Failed, Privilege: {g_lpName}")

    if (g_lpLuid.HighPart == 0) and (g_lpLuid.LowPart == 0):
        sys.exit(f"[!] LookupPrivilegeValueW() Failed, No LUID for privilege: {g_lpName}")
        
    else:
        print(f"\n[+] LookupPrivilegeValueW() Successful, Privilege: {g_lpName}")
        print(f"[+] LUID High: {g_lpLuid.HighPart}, LUID Low: {g_lpLuid.LowPart}")

except Exception as e:
    sys.exit(f"[!] LookupPrivilegeValueW() Failed, Error: {e}")
    
    


###########################################
##### PrivilegeCheck() - advapi32.dll #####
###########################################
#
# NOTE: See Readme.md for caveats to PrivilegeCheck()
#
# func() requires setting up of a number of structures
# - PrivilegeCheck() <- PRIVILEGE_SET() <- LUID_AND_ATTRIBUTES() <- LUID()
# - func() takes a struct of PRIVILEGE_SET
# - which in turn takes a struct of LUID_AND_ATTRIBUTES
# - which in turn takes a struct of LUID
#
# All structs need to be pre-packed
# - all struct arguments need to be assigned
# - LUID already/previously defined for LookupPrivilegeValueW()
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-privilegecheck#return-value

# func() sig
advapi32.PrivilegeCheck.argtypes = [
	wintypes.HANDLE,							# ClientToken
	ctypes.POINTER(PRIVILEGE_SET),	            # RequiredPrivileges
	ctypes.POINTER(wintypes.BOOL)				# pfResult
]
advapi32.PrivilegeCheck.restype = wintypes.BOOL


# CONSTANTS
PRIVILEGE_SET_ALL_NECESSARY = 0x01  # PRIVILEGE_SET()
SE_PRIVILEGE_ENABLED	    = 0X02  # LUID_AND_ATTRIBUTES()
SE_PRIVILEGE_DISABLED	    = 0X00  # LUID_AND_ATTRIBUTES()


# set params for PRIVILEGE_SET() - main struct
req_privs = PRIVILEGE_SET()
req_privs.PrivilegeCount = 1
#req_privs.Control = PRIVILEGE_SET_ALL_NECESSARY # this is fine, as only one priv checked
req_privs.Privilege = LUID_AND_ATTRIBUTES()

# LUID_AND_ATTRIBUTES()
req_privs.Privilege.Luid = g_lpLuid
req_privs.Privilege.Attributes = SE_PRIVILEGE_ENABLED

pfResult = wintypes.BOOL()


if not advapi32.PrivilegeCheck(g_TokenHandle, ctypes.byref(req_privs), ctypes.byref(pfResult)):
    raise ctypes.WinError()
else:
    status = "Enabled" if pfResult.value else "Disabled"
    print(f"\n[+] PrivilegeCheck() Successful, Privilege: {g_lpName}, Status: {status}")


# clean-up of open handles
print("\n[!] Closing opened handles:\n---------------------------")
close_handle(proc_handle, "Process")
close_handle(g_TokenHandle, "AccessToken")
