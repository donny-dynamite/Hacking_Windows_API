"""
Display Windows MessageBox using WinAPI via ctypes
"""

import ctypes
from ctypes import wintypes

# import required DLL
user32 = ctypes.WinDLL('user32.dll', use_last_error=True)

#########################
##### MessageBoxW() #####
#########################
#
# - hWnd not required, but explicity defined for completeness
# - uType, doco defines 4-byte hex value
#          but can also pass short-form, or corresponding integer
#          ie 0x00000030 or 0x30 or 48 (decimal)
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw

# func() sig 
user32.MessageBoxW.argtypes = [
    wintypes.HWND,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.UINT
]    
user32.MessageBoxW.restype = wintypes.INT

# def params
g_hWnd = None 
g_lpText = 'Hello Text'
g_lpCaption = 'Hello Caption'
g_uType = 0x00000001 # MB_OKCANCEL


try:
    ret_code = user32.MessageBoxW(g_hWnd, g_lpText, g_lpCaption, g_uType)
    if not ret_code:
        raise ctypes.WinError()
    print(f"\n[+] MessageBoxW() Successful, Response Code: {ret_code}")

except OSError as e:
    print(f"\n[!] MessageBoxW() Failed, Error: {e}")
