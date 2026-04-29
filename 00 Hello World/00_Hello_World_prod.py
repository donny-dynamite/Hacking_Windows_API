""" Display Windows Message Box """

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
# Function Prototype
# ----------------------------------

user32.MessageBoxW.argtypes = [
    wintypes.HWND,      # hWnd      (None if no owner)
    wintypes.LPCWSTR,   # lpText    (opt)
    wintypes.LPCWSTR,   # lpCaption (opt)
    wintypes.UINT,      # uType 
]    
user32.MessageBoxW.restype = wintypes.INT


# ----------------------------------
# Main functionality starts here
# ----------------------------------

window_text = 'Hello Text'
window_caption = 'Hello Caption'

if not user32.MessageBoxW(None, window_text, window_caption, MB_OKCANCEL):
    raise ctypes.WinError(ctypes.get_last_error())
    
