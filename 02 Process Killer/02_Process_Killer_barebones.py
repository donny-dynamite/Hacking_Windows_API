""" Terminate process for a given window title - barebones """

import ctypes

kernel32 = ctypes.WinDLL('kernel32.dll')
user32 = ctypes.WinDLL('user32.dll')

# get handle for a Window Title
handle_to_window = user32.FindWindowW(None, "Untitled - Notepad")

# get associated process ID
pid = ctypes.c_uint32()
user32.GetWindowThreadProcessId(handle_to_window, ctypes.byref(pid))

# terminate process by handle
proc_handle = kernel32.OpenProcess(0x1F0FFF, False, pid.value)
kernel32.TerminateProcess(proc_handle, 0)
