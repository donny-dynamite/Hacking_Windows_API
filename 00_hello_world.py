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

# display message box
ret_code = u_handle.MessageBoxW(hWnd, lpText, lpCaption, uType)

if not ret_code:
  # Error handling if unable to create MessageBoxW()
  k_handle = ctypes.WinDLL('kernel32.dll')
  error = k_handle.GetLastError()
  print(f"[!] MessageBoxW() Failed, Error Code: {error}")
  sys.exit(1)
else:
  # return response code for button click, not handle value
  print(f"[+] MessageBoxW() Successful, Response Code: {ret_code}")
