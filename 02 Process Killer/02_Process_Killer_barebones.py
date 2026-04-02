"""
Terminate process for a given window title - barebones
"""

import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32.dll')
user32 = ctypes.WinDLL('user32.dll')

# get handle for a Window Title
lpWindowName = "Untitled - Notepad"
hWnd = user32.FindWindowW(None, lpWindowName)

# get associated process ID
lpdwProcessId = wintypes.DWORD()
user32.GetWindowThreadProcessId(hWnd, ctypes.byref(lpdwProcessId))

# get handle to process
hProcess = kernel32.OpenProcess(0x1F0FFF, False, lpdwProcessId.value)

# terminate process
kernel32.TerminateProcess(hProcess, 0)
