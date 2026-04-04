"""
Display Windows Message Box
"""

import ctypes
from ctypes import wintypes

user32 = ctypes.WinDLL('user32.dll', use_last_error=True)


# ----------------------------------
# CONSTANTS
# ----------------------------------

# uType for MessageBoxW() - samples
MB_OK                   = 0x00
MB_OKCANCEL             = 0x01
MB_ABORTRETRYIGNORE     = 0x02
MB_YESNOCANCEL          = 0x03
MB_YESNO                = 0x04




# ----------------------------------
# Function Signature
# ----------------------------------

user32.MessageBoxW.argtypes = [
    wintypes.HWND,      # hWnd      (can be None, no owner)
    wintypes.LPCWSTR,   # lpText    (opt)
    wintypes.LPCWSTR,   # lpCaption (opt)
    wintypes.UINT,      # uType 
]    
user32.MessageBoxW.restype = wintypes.INT




# ----------------------------------
# Main functionality starts here
# ----------------------------------

# def params for MessageBoxW()
hWnd = None
lpText = 'Hello Text'
lpCaption = 'Hello Caption'
uType = MB_OKCANCEL


try:
    ret_code = user32.MessageBoxW(hWnd, lpText, lpCaption, uType)
    if ret_code == 0:
        raise ctypes.WinError(ctypes.get_last_error())

    # return code depends on icon clicked in message box
    print(f"\n[+] MessageBoxW() Successful, Return Code: {ret_code}")

except OSError as e:
    print(f"\n[!] MessageBoxW() Failed, Error: {e}")
