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
# return HANDLE to open process
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights

# func() sigs
kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD
]
kernel32.OpenProcess.restype = wintypes.HANDLE

# for handle cleanup
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

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
    return ret


proc_handle = None


try:
    proc_handle = open_proc(g_dwDesiredAccess, g_bInheritHandle, g_dwProcessId)
    print(f"\n[+] OpenProcess() Successful, Process Handle: {proc_handle}")

except OSError as e:
    print(f"\n[!] OpenProcess() Failed. Error: {e}")



            
#############################################
##### OpenProcessToken() - advapi32.dll #####
#############################################
# 
# return Handle to Access Token ... or rather:
# - update Pointer var (TokenHandle) to contain HANDLE
# - that refers to Access Token for given process
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
g_ProcessHandle = proc_handle
g_DesiredAccess = 0xF01FF # BitMask for TOKEN_ALL_ACCESS
g_TokenHandle = wintypes.HANDLE()


# func() wrapper for OpenProcessToken()
def open_proc_token(ProcessHandle, DesiredAccess, TokenHandle):
    ret = advapi32.OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(TokenHandle))
    if not ret:
        raise ctypes.WinError()    
    return ret


try:
    opt = open_proc_token(g_ProcessHandle, g_DesiredAccess, g_TokenHandle)
    print(f"[+] OpenProcessToken() Successful, Return Code: {opt}")

except OSError as e:
    print(f"[!] OpenProcessToken() Failed, Error: {e}")

finally:
    # probably put this in a separate fun() to make simpler
    print("\n[!] Closing opened handles:\n---------------------------")

    # close HANDLE to Process
    if proc_handle not in (None, 0):
        handle_close = kernel32.CloseHandle(proc_handle)
        if handle_close:
            print(f"[+] CloseHandle() on Process Successful, Handle: {proc_handle}")
            proc_handle = None
        else:
            error = kernel32.GetLastError()
            print(f"[!] CloseHandle() on Process Failed, Error: {error}")

    # close HANDLE to Access Token
    if g_TokenHandle not in (None, 0):
        handle_close = kernel32.CloseHandle(g_TokenHandle)
        if handle_close:
            print(f"[+] CloseHandle() on Access Token Successful, Handle: {g_TokenHandle.value}")
            g_TokenHandle = None
        else:
            error = kernel32.GetLastError()
            print(f"[!] CloseHandle() on Access Token Failed, Error: {error}")
