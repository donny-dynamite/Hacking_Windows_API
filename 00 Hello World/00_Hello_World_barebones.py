""" Display Windows Message Box """

import ctypes

user32 = ctypes.WinDLL('user32.dll')
user32.MessageBoxW(None, 'Hello Text', 'Hello Caption', 1)
