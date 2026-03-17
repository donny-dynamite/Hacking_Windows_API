# module for WinAPI function calls
import ctypes

# define parameters for MessageBoxW function call
# https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw

# Note for uType - MS doco defines 4-byte long integer in hex
# but function can also be passed short-form hex, or corresponding integer
# ie 0x00000030 or 0x30 or 48 (decimal)
hWnd = None    # not needed here
lpText = 'Hello Text'
lpCaption = 'Hello Caption'
uType = 0x00000001

# create handles to user32.dll (message box) and kernel32.dll (error code)
u_handle = ctypes.WinDLL('user32.dll')
k_handle = ctypes.WinDLL('kernel32.dll')

# display message box, and return code
response = u_handle.MessageBoxW(hWnd, lpText, lpCaption, uType)
print(f"Response code: {response}")

# Note for error code:
# if code run line by line in an interactive session/interpreter, non-zero value returned
# does not indicate script error, rather left-over error code from within session itself
error = k_handle.GetLastError()
print(f"Error code: {error}")
