"""
Open a handle to an existing process, using WinAPI via ctypes
- utilises PowerShell scripts for PID validation
"""

import ctypes
from ctypes import wintypes
import subprocess
import sys


kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)


##############################
##### PowerShell scripts #####
##############################
#
# - list PIDs, grouped by ProcessName (raw string is okay here)
# - loop for a valid integer to be entered
# - validate entered integer exists as a PID in tasklist/Get-Process

# list PIDs, grouped by ProcessName (raw string is okay here)
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




#########################
##### CloseHandle() #####
#########################
#
# for clean-up of open handles at the end of execution
# 
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle#return-value

# func() sig
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

# wrapper for CloseHandle()
def close_handle(handle, name="Handle"):
    if handle:
        if kernel32.CloseHandle(handle):
            print(f"[+] CloseHandle() Successful, {name} Handle: {handle.value}")
            
        else:
            print(f"[!] CloseHandle() Failed, {name}: {handle.value}, Error: {ctypes.get_last_error()}")




#########################
##### OpenProcess() #####
#########################
#
# Return HANDLE to open process
# - force return type of HANDLE in func() wrapper, otherwise ctypes converts to type 'int'
# - return wintypes.HANDLE(ret)
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights

# func() sig
kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD
]
kernel32.OpenProcess.restype = wintypes.HANDLE

# def params
PROCESS_ALL_ACCESS = 0x1F0FFF # likely to fail unless run elevated/as-admin
# PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
g_dwDesiredAccess = PROCESS_ALL_ACCESS
g_bInheritHandle = False
g_dwProcessId = pid_value


# wrapper for OpenProcess()
def open_proc(dwDesiredAccess, bInheritHandle, dwProcessId):
    ret = kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    if not ret:
        raise ctypes.WinError()    
    return wintypes.HANDLE(ret)


# so that finally: works in case try:/except: fails
proc_handle = None 


try:
    proc_handle = open_proc(g_dwDesiredAccess, g_bInheritHandle, g_dwProcessId)
    print(f"\n[+] OpenProcess() Successful, Process Handle: {proc_handle.value}")

except Exception as e:
    print(f"\n[!] OpenProcess() Failed. Error: {e}")

finally:
    if proc_handle and proc_handle.value:
        print("\n[!] Closing opened handles:\n---------------------------")
        close_handle(proc_handle, "Process")
