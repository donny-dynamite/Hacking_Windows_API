"""
(barebones) Open handle to Access Token for a given process

Steps:
------
- OpenProcess() for given PID
- OpenProcessToken() for returned process handle

"""

import ctypes
from ctypes import wintypes


# import DLLs
kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32.dll', use_last_error=True)

# get handle to PID
PROC_ID = <CHANGE ME>
proc_handle = wintypes.HANDLE(kernel32.OpenProcess(0x1F0FFF, False, PROC_ID))

# get handle to access token for given process
token_handle = wintypes.HANDLE()
advapi32.OpenProcessToken(proc_handle, 0xF01FF, ctypes.byref(token_handle))

# cleanup resources
kernel32.CloseHandle(proc_handle)
kernel32.CloseHandle(token_handle)
