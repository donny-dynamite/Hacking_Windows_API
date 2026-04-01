"""
Display Windows MessageBox using WinAPI via ctypes
- minimal code/functionality implementation
"""

import ctypes
from ctypes import wintypes

user32 = ctypes.WinDLL('user32.dll', use_last_error=True)

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

######################################
##### MessageBoxW() - user32.dll #####
######################################
#
# - hWnd not required, but explicity defined for completeness
# - uType, doco defines 4-byte hex value -> can also pass short-form (0x30) or decimal (48)

try:
    ret_code = user32.MessageBoxW(g_hWnd, g_lpText, g_lpCaption, g_uType)
    if not ret_code:
        raise ctypes.WinError()
    print(f"\n[+] MessageBoxW() Successful, Return Code: {ret_code}")

except OSError as e:
    print(f"\n[!] MessageBoxW() Failed, Error: {e}")
