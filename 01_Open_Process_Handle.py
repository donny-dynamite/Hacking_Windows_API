import ctypes
import subprocess
import sys

k_handle = ctypes.WinDLL('kernel32.dll')

# Run PowerShell script - list PIDs, grouped by ProcessName
script = r'''
Get-Process | Group-Object ProcessName | % {
    [PSCustomObject]@{
        ProcessName = $_.Name
        PIDs = ($_.Group.Id -join ", ")
    }
}
'''

result = subprocess.run(
    ["powershell", "-command", script],
    capture_output=True,
    text=True
)

print(result.stdout)

try:
    PID = int(input("Enter a single PID from above list: "))
except ValueError as e:
    sys.exit(f"[!] Invalid integer, Error: {e}\n")


# Define OpenProcess() parameters
# Ref PROCESS_ALL_ACCESS: https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights

PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFFF)
dwDesiredAccess = PROCESS_ALL_ACCESS
bInheritHandle = False
dwProcessId = PID

response = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)

if not response:
    error = k_handle.GetLastError()
    print(f"[!] OpenProcess() failed, Error Code: {error}")
else:
    print(f"[+] OpenProcess() succeeded, Handle: {response}")
