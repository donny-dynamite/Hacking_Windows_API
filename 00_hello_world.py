# module for WinAPI function calls
import ctypes
import sys

# define parameters for MessageBoxW function call
# https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw

# Note for uType - MS doco defines 4-byte long integer in hex
# but function can also be passed short-form hex, or corresponding integer
# ie 0x00000030 or 0x30 or 48 (decimal)
hWnd = None    # not needed here
lpText = 'Hello Text'
lpCaption = 'Hello Caption'
uType = 0x00000001

# create handles to user32.dll, MessageBoxW()
u_handle = ctypes.WinDLL('user32.dll')

# display message box, and return code
response = u_handle.MessageBoxW(hWnd, lpText, lpCaption, uType)

if not response:
  # Error handling if unable to retrieve handle
  k_handle = ctypes.WinDLL('kernel32.dll')
  error = k_handle.GetLastError()
  print(f"[!] MessageBoxW() failed, Error Code: {error}")
  sys.exit(1)
else:
  print(f"[+] MessageBoxW() successful, Handle: {response}")
