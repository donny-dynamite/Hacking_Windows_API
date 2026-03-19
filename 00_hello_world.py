# module for WinAPI function calls
import ctypes

# load required DLL for MessageBoxW()
user32 = ctypes.WinDLL('user32.dll')

# Ref: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw
# Note for uType, doco defines 4-byte long integer in hex
# can also passed short-form hex, or corresponding integer
# ie 0x00000030 or 0x30 or 48 (decimal)
hWnd = None
lpText = 'Hello Text'
lpCaption = 'Hello Caption'
uType = 0x00000001

# call MessageBoxW()
ret_code = user32.MessageBoxW(hWnd, lpText, lpCaption, uType)

if ret_code:
  # returns response code for button that was clicked, NOT handle value
  print(f"[+] MessageBoxW() Successful, Response Code: {ret_code}")
else:
  # Error handling if unable to create MessageBoxW()
  kernel32 = ctypes.WinDLL('kernel32.dll')
  error = kernel32.GetLastError()
  print(f"[!] MessageBoxW() Failed, Error Code: {error}")
