"""
Display Windows MessageBox using WinAPI via ctypes
func() def to wrap MessageBoxW() API call
"""

import ctypes
from ctypes import wintypes


###############################
##### Function Signatures #####
###############################
user32 = ctypes.WinDLL('user32.dll', use_last_error=True)

user32.MessageBoxW.argtypes = [
    wintypes.HWND,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.UINT
]    
user32.MessageBoxW.restype = wintypes.INT

# define parameters
# ref: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw
#
# whilst hWnd not necessary, explicity defined as standard
#
# for uType, doco defines 4-byte long integer in hex, can also pass short-form, or corresponding integer
# ie 0x00000030 or 0x30 or 48 (decimal)

global_hWnd = None 
global_lpText = 'Hello Text'
global_lpCaption = 'Hello Caption'
global_uType = 0x00000001 # MB_OKCANCEL


# func() def to call MessageBoxW()
def msg_box(hWnd, lpText, lpCaption, uType):
    ret = user32.MessageBoxW(hWnd, lpText, lpCaption, uType)
    if ret == 0:
        raise ctypes.WinError()
    return ret


try:
    ret_code = msg_box(global_hWnd, global_lpText, global_lpCaption, global_uType)
    print(f"\n[+] MessageBoxW() Successful, Response Code: {ret_code}")
except OSError as e:
    print(f"\n[!] MessageBowX() Failed, Error: {e}")
