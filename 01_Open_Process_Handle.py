"""
Open a handle to an existing process, using WinAPI via ctypes
Calls PowerShell script to group PIDs by ProcessName
"""

import ctypes
from ctypes import wintypes
import subprocess


# Run PowerShell script - list PIDs, grouped by ProcessName (raw string is okay here)
script = r'''
Get-Process | Group-Object ProcessName | % {
    [PSCustomObject]@{
        ProcessName = $_.Name
        PIDs = ($_.Group.Id -join ", ")
    }
}
'''

pid_list = subprocess.run(["powershell", "-command", script], capture_output=True, text=True)
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



#################################
##### Function Signature(s) #####
#################################
kernel32 = ctypes.WinDLL('kernel32.dll')

kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD
]
kernel32.OpenProcess.restype = wintypes.HANDLE


# define parameters
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights

PROCESS_ALL_ACCESS = 0x1F0FFF
g_dwDesiredAccess = PROCESS_ALL_ACCESS
g_bInheritHandle = False
g_dwProcessId = pid_value


# func() def to call OpenProcess()
def open_proc(dwDesiredAccess, bInheritHandle, dwProcessId):
    ret = kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    if not ret:
        raise ctypes.WinError()    
    return ret


try:
    pHandle = open_proc(g_dwDesiredAccess, g_bInheritHandle, g_dwProcessId)
    print(f"\n[+] OpenProcess() Successful, Process Handle: {pHandle}")
except OSError as e:
    print(f"\n[!] OpenProcess() Failed. Error: {e}")
