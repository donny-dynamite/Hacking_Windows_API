'''
Terminate process for a given window title

API calls used:
---------------
FindWindowW()
- retrieve window handle (HWND) for specified window title
- uses Unicode variant to avoid encoding issues

GetWindowThreadProcessId()
- obtain process ID (PID) associated with window handle

OpenProcess()
- open a handle to target process using retrieved PID

TerminateProcess()
- terminate process associated with opened handle
'''

import ctypes
from ctypes import wintypes
import subprocess
import sys


# load required DLLs 
user32   = ctypes.WinDLL('user32.dll',   use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)


########################################
###### FindWindowW() - user32.dll ######
########################################
'''
Step 1: Enter process name -> check if exists
Step 2: Return window titles as list
Step 3: Select title based off index (0-base)
Step 4: Retrieve window handle (HWND) to selected title
'''

# Step 1: Enter process name -> check if exists
proc_name = input("\nEnter name of process: ")

proc_check = subprocess.run(
    ["powershell", "-NoProfile", "-Command", "Get-Process", "-Name", proc_name],
    capture_output=True, text=True
)

if not proc_check.stdout.strip():
    sys.exit(f"\n[!] ProcessName '{proc_name}' not found. Exiting.")


# Step 2: Return window titles as list
ps_script = f'''
    Get-Process -Name "{proc_name}" -EA 0 |
    Where-Object {{ $_.MainWindowTitle }} |
    ForEach-Object {{ $_.MainWindowTitle }}
'''

ps_titles = subprocess.run(
    ["powershell", "-NoProfile", "-Command", ps_script],
    capture_output=True, text=True
)

window_titles = [line.strip() for line in ps_titles.stdout.splitlines() if line.strip()]

if not window_titles:
    sys.exit(f"[!] No visible windows found for process '{proc_name}': Exiting.")
else:
    print("\nAvailable Window Titles:\n------------------------")
    for i, title in enumerate(window_titles, start=0):
        print(f"[{i}]: {title}")


# Step 3: Select title based off index (0-base)
while True:
    try:
        window_choice = int(input("\nSelect number for window title: "))
        # if ((window_choice >= 0) and (window_choice < len(window_titles)):
        if 0 <= window_choice < len(window_titles):
            title_choice = window_titles[window_choice]
            break
        else:
            print(f"[!] Please enter a number between 0 and {len(window_titles) -1}.")
    except ValueError:
        print("[!] Invalid input. Please enter a number from above.")


# Step 4: Retrieve window handle (HWND) to selected title
#
# Ref FindWindowW() - https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-FindWindowW

# def func() sigs and params
user32.FindWindowW.argtypes = [
    wintypes.LPCWSTR,   # lpClassName
    wintypes.LPCWSTR    # lpWindowName
]
user32.FindWindowW.restype = wintypes.HWND

g_lpClassName = None
g_lpWindowName = title_choice


# func() def to wrap FindWindowW()
def find_window(lpClassName, lpWindowName):
    ret = user32.FindWindowW(lpClassName, lpWindowName)
    if not ret:
        raise ctypes.WinError()
    return ret


try:
    fwa_hWnd = find_window(g_lpClassName, g_lpWindowName)
    print(f"\n[+] FindWindowW() Successful, Window Handle: {fwa_hWnd}\n")
except OSError as e:
    sys.exit(f"\n[!] FindWindowW() Failed, Error Code: {e}\n")




#####################################################
###### GetWindowThreadProcessId() - user32.dll ######
#####################################################
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowthreadprocessid
# LPDWORD lpdwProcessId - output parameter, therefore value to be stored in prepared variable (DWORD)

# def func() sigs and params
user32.GetWindowThreadProcessId.argtypes =[
    wintypes.HWND,      # hWnd
    wintypes.LPDWORD    # lpdwProcessId
]
user32.GetWindowThreadProcessId.restype  = wintypes.DWORD

g_hWnd = fwa_hWnd # from above ret for FindWindowW()
g_lpdwProcessId = ctypes.wintypes.DWORD()


# func() def to wrap GetWindowThreadProcessId()
def get_thread(hWnd, lpdwProcessId):
    ret = user32.GetWindowThreadProcessId(hWnd, lpdwProcessId)
    if not ret:
        raise ctypes.WinError()
    return ret
 
 
try:
    thread_id = get_thread(g_hWnd, ctypes.byref(g_lpdwProcessId))
    print(f"[+] GetWindowThreadProcessId() Successful:")
    print(f"\tProcess: {proc_name}")
    print(f"\tThread ID: {thread_id}")
    print(f"\tProcess ID: {g_lpdwProcessId.value}")
except OSError as e:
    sys.exit(f"\n[!] GetWindowThreadProcessId() Failed, Error Code: {e}")




##########################################
###### OpenProcess() - kernel32.dll ######
##########################################
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess

# def func() sigs and params
kernel32.OpenProcess.argtypes = [
    wintypes.DWORD, # dwDesiredAccess
    wintypes.BOOL,  # bInheritHandle
    wintypes.DWORD  # dwProcessId
]
kernel32.OpenProcess.restype = wintypes.HANDLE

PROCESS_ALL_ACCESS = 0x1F0FFF

g_dwDesiredAccess = PROCESS_ALL_ACCESS
g_bInheritHandle = False
g_dwProcessId = g_lpdwProcessId.value   # from GetWindowThreadProcessId() above


# func() def to wrap OpenProcess()
def open_handle(dwDesiredAccess, bInheritHandle, dwProcessId):
    ret = kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    if not ret:
        raise ctypes.WinError()
    return ret


try:
    proc_handle = open_handle(g_dwDesiredAccess, g_bInheritHandle, g_dwProcessId)
    print(f"\n[+] OpenProcess() Successful, Process Handle: {proc_handle}")
except OSError as e:
    sys.exit(f"\n[!] OpenProcess() Failed, Error Code: {e}")




###############################################
###### TerminateProcess() - kernel32.dll ######
###############################################
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess

# def func() sigs and params
kernel32.TerminateProcess.argtypes = [
    wintypes.HANDLE,    # hProcess
    wintypes.UINT       # uExitCode
]
kernel32.TerminateProcess.restype = wintypes.BOOL

# for final cleanup
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

g_hProcess = proc_handle    # from OpenProcess() above
g_uExitCode = 0


def kill_proc(hProcess, uExitCode):
    ret = kernel32.TerminateProcess(hProcess, uExitCode)
    if not ret:
        raise ctypes.WinError()
    return ret


try:
    term_proc = kill_proc(g_hProcess, g_uExitCode)
    print(f"\n[+] TerminateProcess() Successful, Process ID killed: {g_dwProcessId}")
except OSError as e:
    sys.exit(f"\n[!] TerminateProcess() Failed, Error Code: {e}")
finally:
    if g_hProcess:
        kernel32.CloseHandle(g_hProcess)
