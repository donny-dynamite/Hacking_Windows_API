import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32.dll')

PROCESS_ALL_ACCESS = 0x1F0FFF

# two methods to create handle to current process
# method 1
pid = kernel32.GetCurrentProcessId()
pHandle = kernel32.OpenProcess(PROCESS_ALL_ACCES, False, pid)

# method 2 - pseudo-handle
pHandle = kernel32.GetCurrentProcess()
