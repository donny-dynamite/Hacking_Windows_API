"""
Display Windows Message Box
"""

import ctypes
from ctypes import wintypes

user32 = ctypes.WinDLL('user32.dll')

lpText = 'Hello Text'
lpCaption = 'Hello Caption'

user32.MessageBoxW(None, lpText, lpCaption, 1)
