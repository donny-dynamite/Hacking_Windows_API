""" Get handle to a/current process """
import ctypes

kernel32 = ctypes.WinDLL('kernel32.dll')

# method 1 (or other non-current based on pid)
pid = kernel32.GetCurrentProcessId()
pHandle = kernel32.OpenProcess(0x1F0FFF, False, pid)

# method 2 - pseudo-handle
pHandle = kernel32.GetCurrentProcess()
