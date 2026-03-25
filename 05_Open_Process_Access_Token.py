"""
Open Access Token for a given process - display privileges
- extends on previous Open_Process_Handle.py

Steps:
- PowerShell script to list PIDs, group-by ProcessName
- OpenProcess() for given PID
- OpenProcessToken() for returned process handle
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
# - loop for valid integer to be entered
# - validate entered value exists as a PID

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




########################################
##### OpenProcess() - kernel32.dll #####
########################################
# 
# Return HANDLE to open process
# - force return type of HANDLE, otherwise ctypes converts to int
#
# In final CloseHandle()
# - ensures consistency when calling CloseHandle() during cleanup
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
PROCESS_ALL_ACCESS = 0x1F0FFF # BitMask value
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




#########################
##### CloseHandle() #####
#########################
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

finally:
    print("\n[!] Closing opened handles:\n---------------------------")

    close_handle(proc_handle, "Process")
    close_handle(g_TokenHandle, "AccessToken")
