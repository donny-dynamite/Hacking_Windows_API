import ctypes
import subprocess

kernel32 = ctypes.WinDLL('kernel32.dll')

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
        pid_value = int(input("Enter a single PID from above list: "))
        if pid_value:
            break
        else:
            print(f"Please enter single PID from above list")
    except ValueError as e:
        print(f"\n[!] Invalid Input, Error: {e}")




#########################
##### OpenProcess() #####
#########################
# Ref: https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights

PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFFF)
dwDesiredAccess = PROCESS_ALL_ACCESS
bInheritHandle = False
dwProcessId = pid_value

try:
    proc_handle = kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    if proc_handle:
        print(f"\n[+] OpenProcess() Successful, Process Handle: {proc_handle}")
    else:
        raise ctypes.WinError()
except Exception as e:
    print(f"\n[!] OpenProcess() Failed. Error Code: {e.winerror}, Message: {e.strerror}")
