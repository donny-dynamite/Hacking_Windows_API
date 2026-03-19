import ctypes
from ctypes import wintypes
import subprocess
import sys

'''
API Calls to find process by Window Title, then terminate
- FindWindowA()
- GetWindowThreadProcessId()
- OpenProcess()
- TerminateProcess()
'''

# load required DLLs 
user32 = ctypes.WinDLL('user32.dll')
kernel32 = ctypes.WinDLL('kernel32.dll')




########################################
###### FindWindowA() - user32.dll ######
########################################

'''
Step 1: Enter process name -> check if exists
Step 2: Return Window Titles as list
Step 3: Select window based off index (0-base)
Step 4: Open handle to selected item
'''

# Step 1: Enter process name -> check if exists
procName = input("\nEnter name of process: ")

check_script = f"Get-Process -Name '{procName}' -EA 0"
check_result = subprocess.run(
    ["powershell", "-NoProfile", "-Command", check_script],
    capture_output = True, text = True
)

if not check_result.stdout.strip():
    print(f"\n[!] ProcessName '{procName}' not found. Exiting.")
    sys.exit(1)

# Step 2: Return Window Titles as list
ps_script = f"""
    Get-Process -Name '{procName}' -EA 0 |
    Where-Object {{$_.MainWindowTitle}} |
    ForEach-Object {{$_.MainWindowTitle}}
"""

script_result = subprocess.run(
    ["powershell", "-NoProfile", "-Command", ps_script],
    capture_output=True, text=True
)

window_titles = [line.strip() for line in script_result.stdout.splitlines() if line.strip()]

if not window_titles:
    print(f"[!] No visible windows found for process '{procName}': Exiting.")
    sys.exit(1)
else:
    print("\nAvailable Window Titles:")
    for i, title in enumerate(window_titles, start=0):
        print(f"[{i}]: {title}")

# Step 3: Select window based off index (0-base)
while True:
    try:
        window_choice = int(input("\nSelect number for window title: "))
        # if ((window_choice >= 0) and (window_choice < len(window_titles)):
        if 0 <= window_choice < len(window_titles):
            selected_title = window_titles[window_choice]
            break
        else:
            print(f"[!] Please enter a number between 0 and {len(window_titles)}.")
    except ValueError:
        print("[!] Invalid input. Please enter a number from above.")


# Step 4: Open handle to selected item
# Ref FindWindowA() - https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindowa
lpClassName = None
lpWindowName = selected_title.encode('utf-8')

fwa_hWnd = user32.FindWindowA(lpClassName, lpWindowName)

if fwa_hWnd:
    print(f"\n[+] FindowWindowA() Successful, Window Handle: {fwa_hWnd}\n")
else:
    error = kernel32.GetLastError()
    print(f"\n[!] FindWindowA() Failed, Error Code: {error}\n")
    sys.exit(1)




#####################################################
###### GetWindowThreadProcessId() - user32.dll ######
#####################################################
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowthreadprocessid
# LPDWORD lpdwProcessId - output parameter, therefore value to be stored in prepared variable (DWORD)

'''
Step 1: Prep paramaters, inc output parameter
Step 2: Call GetWindowThreadProcessId and store value in variable
'''

# Step 1: Prep paramaters, inc variable to receive DWORD
hWnd = fwa_hWnd
lpdwProcessId = ctypes.wintypes.DWORD()

# Step 2: Call GetWindowThreadProcessId and store value in variable
thread_id = user32.GetWindowThreadProcessId(hWnd, ctypes.byref(lpdwProcessId))
if thread_id:
    print(f"[+] GetWindowThreadProcessId() Successful:")
    print(f"\tProcess: {procName}")
    print(f"\tThread ID: {thread_id}")
    print(f"\tProcess ID: {lpdwProcessId.value}")
else:
    error = kernel32.GetLastError()
    print(f"\n[!] GetWindowThreadProcessId() Failed, Error Code: {error}")
    sys.exit(1)




##########################################
###### OpenProcess() - kernel32.dll ######
##########################################
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess

PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFFF)
dwDesiredAccess = PROCESS_ALL_ACCESS
bInheritHandle = False
dwProcessId = lpdwProcessId

proc_handle = kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)

if proc_handle:
    print(f"\n[+] OpenProcess() Successfull, Process Handle: {proc_handle}")
else:
    error = kernel32.GetLastError()
    print(f"\n[!] OpenProcess() Failed, Error Code: {error}")




###############################################
###### TerminateProcess() - kernel32.dll ######
###############################################
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess

hProcess = proc_handle
uExitCode = 0

term_proc = kernel32.TerminateProcess(hProcess, uExitCode)

if term_proc:
    print(f"\n[+] TerminateProcess() Successful, Process ID killed: {dwProcessId.value}")
else:
    error = kernel32.GetLastError()
    print(f"\n[!] TerminateProcess() Failed, Error Code: {error}")
    sys.exit(1)
