"""
Flip status of selected Privilege listed in access token
- ENABLED -> DISABLED and vice versa

Note: needs heavy re-factor
- messay as hell
- currently just POC to prove code works, cleanup afterwards

Steps:
- PowerShell script to list PIDs, group-by ProcessName
- OpenProcess() for given PID
- OpenProcessToken() for returned process handle
- GetTokenInformation(TokenPrivileges)
- LookupPrivilegeNameW()
"""

#### REFACTOR IDEAS
#
# ARRAYS
# - ensure last element in ANY array has comma (standardise)
#
# Flipping
# - remove confirmation
# - once index selected, show before, and after confirmation
#
# Fix up the last half


import ctypes
from ctypes import wintypes
import subprocess
import sys


kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32.dll', use_last_error=True)


################################
##### PowerShell script(s) #####
################################
#
# - list PIDs, grouped by ProcessName (raw string is okay here)
# - loop for a valid integer to be entered
# - validate entered integer exists as a PID in tasklist/Get-Process

# list PIDs, groupBy ProcessName
script = r'''
Get-Process | Group-Object ProcessName | % {
    [PSCustomObject]@{
        ProcessName = $_.Name
        PIDs = ($_.Group.Id -join ", ")
    }
}
'''

pid_list = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True, text=True)
print(pid_list.stdout)


# loop for valid integer to be entered
while True:
    try:
        pid_value = int(input("\nPlease enter a valid PID: "))
        if pid_value <= 0:
            print("[!] Please enter a positive integer: ")
            continue
        break

    except ValueError as e:
        print(f"\n[!] Invalid Input, Error: {e}")


# validate entered PID
valid_pid = subprocess.run(["powershell", "-NoProfile", "-Command", f"Get-Process -ID {pid_value}"], capture_output=True, text=True)
if not valid_pid.stdout.strip():
    sys.exit(f"[!] PID {pid_value} non-existant. Exiting")




#####################
##### CONSTANTS #####
#####################

# Attributes field in LUID_AND_ATTRIBUTES struct
# BitMask values that can be used in combination
SE_PRIVILEGE_DISABLED	        = 0X00
SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0X01
SE_PRIVILEGE_ENABLED	        = 0X02
SE_PRIVILEGE_REMOVED            = 0x04
SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000

# OpenProcess() - BitMask values
PROCESS_QUERY_LIMITED_INFORMATION   = 0x1000
PROCESS_ALL_ACCESS                  = 0x1F0FFF

# OpenProcessToken() - BitMask values
TOKEN_ALL_ACCESS = 0xF01FF




###################
##### Structs #####
###################
#
# LUID (Locally Unique ID)
# - 64-bit value used to identify privileges
# - two parts, lower/higher 32bits (LSB/MSB)
# - LUID > 0 if valid, ie:
# if (LowPart == 0) and (HighPart == 0):
#     sys.exit(f"[!] Error, LUID not found")
#
# LUID_AND_ATTRIBUTES
# - specifies properties of a privilege - DISABLED, ENABLED, REMOVED etc
# - BitMask values defined in CONSTANTS

class LUID(ctypes.Structure):
	_fields_ = [
        ("LowPart",		wintypes.DWORD),
        ("HighPart", 	wintypes.LONG),
	]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
	_fields_ = [
        ("Luid", 		LUID),
        ("Attributes", 	wintypes.DWORD),
	]

# dynamic struct creation, to handle variable-length access tokens
def createStruct_tokenPrivileges(length):
    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [
            ("PrivilegeCount",  wintypes.DWORD),
            ("Privileges",      LUID_AND_ATTRIBUTES * length),
        ]
    return TOKEN_PRIVILEGES
    



###############################
##### Function Signatures #####
###############################
#
# to ensure functions passed (and return) correct data types

## kernel32
kernel32.CloseHandle.argtypes = [wintypes.HANDLE,]  # hObject
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.OpenProcess.argtypes = [
    wintypes.DWORD, # dwDesiredAccess
    wintypes.BOOL,  # bInheritHandle
    wintypes.DWORD, # dwProcessId
]
kernel32.OpenProcess.restype = wintypes.HANDLE


## advapi32
advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE,                    # ProcessHandle
    wintypes.DWORD,                     # DesiredAccess
    ctypes.POINTER(wintypes.HANDLE),    # [o] TokenHandle
]
advapi32.OpenProcessToken.restype = wintypes.BOOL

advapi32.LookupPrivilegeNameW.argtypes = [
    wintypes.LPCWSTR,               # lpSystemName
    ctypes.POINTER(LUID),           # lpLuid
    wintypes.LPWSTR,                # [o] lpName (opt)
    ctypes.POINTER(wintypes.DWORD), # cchName (size)
]
advapi32.LookupPrivilegeNameW.restype = wintypes.BOOL

advapi32.GetTokenInformation.argtypes = [
    wintypes.HANDLE,                # TokenHandle
    wintypes.INT,                   # TokenInformationClass
    ctypes.c_void_p,                # [o] TokenInformation (buffer) (opt)
    wintypes.DWORD,                 # TokenInformationLength
    ctypes.POINTER(wintypes.DWORD), # [o] ReturnLength
]
advapi32.GetTokenInformation.restype = wintypes.BOOL

# NOTE: NewState/PreviousState -> ctypes.c_void_p as workaround
# - originally -> ctypes.POINTER(TOKEN_PRIVILEGES)
# - however NameError thrown as struct not defined yet
advapi32.AdjustTokenPrivileges.argtypes = [
    wintypes.HANDLE,                    # TokenHandle
    wintypes.BOOL,                      # DisableAllPrivileges
    ctypes.c_void_p,                    # NewState (opt)
    wintypes.DWORD,                     # BufferLength
    ctypes.c_void_p,                    # [o] PreviousState (opt)
    ctypes.POINTER(wintypes.DWORD),     # [o] ReturnLength (opt)
]
advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL




########################################
##### CloseHandle() - kernel32.dll #####
########################################
#
# final cleanup
def close_handle(handle, name="Handle"):
    if handle:
        if kernel32.CloseHandle(handle):
            print(f" -> CloseHandle() Successful, {name} Handle: {handle.value}")
        else:
            print(f"[!] CloseHandle() Failed, {name}: {handle.value}, Error: {ctypes.get_last_error()}")




########################################
##### OpenProcess() - kernel32.dll #####
########################################
#
# return open HANDLE to specified process

dwDesiredAccess = PROCESS_ALL_ACCESS
bInheritHandle = False
dwProcessId = pid_value

def open_proc(dwDesiredAccess, bInheritHandle, dwProcessId):
    ret = kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    if not ret:
        raise ctypes.WinError()    
    return wintypes.HANDLE(ret)


try:
    ProcessHandle = open_proc(dwDesiredAccess, bInheritHandle, dwProcessId)
    print(f"\n[+] OpenProcess() Successful, Process Handle: {ProcessHandle.value}")

except OSError as e:
    sys.exit(f"\n[!] OpenProcess() Failed. Error: {e}")



#############################################
##### OpenProcessToken() - advapi32.dll #####
#############################################
# 
# update TokenHandle to contain HANDLE to Access Token for given process
# - no return value, updating pointer in-place

DesiredAccess = TOKEN_ALL_ACCESS
TokenHandle = wintypes.HANDLE()

try:
    if not advapi32.OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(TokenHandle)):
        raise ctypes.WinError()
    print(f"[+] OpenProcessToken() Successful, AccessToken Handle: {TokenHandle.value}")

except OSError as e:
    sys.exit(f"[!] OpenProcessToken() Failed, Error: {e}")








#################################################
##### GetTokenInformation () - advapi32.dll #####
#################################################
#
# Third argument passed to func():
# - [out, opt] LPVOID TokenInformation
# - from doco, "The structure put into this buffer, depends upon the TokenInformationClass"
# - struct type is not fixed, can be passed TOKEN_GROUPS, TOKEN_USER, TOKEN_OWNER etc
# - therefore defined as ctypes.c_void_p, not ctypes.POINTER()

# Specify information to retrieve from access token
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
TokenInformationClass = 3       # TokenPrivileges


###############################################################################
##### NOTE: REFACTOR whole section into a function for re-use #####
###############################################################################

# GetTokenInformation() - cast struct with proper buffer size for variable-length array
# 
# Step 1 - retrieve proper buffer size, with first GetTokenInformation() call
# Step 2 - allocate proper-sized buffer variable
# Step 3 - retrieve full buffer, requesting TokenPrivileges class
# Step 4* - ret PrivilegeCount (array length)
# Step 5 - re-build proper struct with correct array length
# Step 6 - re-cast buffer-memory into new struct

##### Note about Step 4
# Here we do NOT cast buffer to a base/temporary struct
# - this method directly re-interprets/casts buffer, as if it points to a DWORD
# 
# memory layout of struct/buffer already known (as defined in struct layout)
# [DWORD PrivilegeCount]
# [LUID_AND_ATTRIBUTES #1]
# [LUID_AND_ATTRIBUTES #2]
# [LUID_AND_ATTRIBUTES #n]
#
# array_length = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value
# - this avoids casting to a struct twice, and pulls value directly from buffer
# - from the first DWORD/4-bytes of the buffer, which is where PrivilegeCount sits

# Step 1
size = wintypes.DWORD() 
advapi32.GetTokenInformation(TokenHandle, TokenInformationClass, None, 0, ctypes.byref(size))

# Step 2
buf = ctypes.create_string_buffer(size.value) 

# Step 3
if not advapi32.GetTokenInformation(TokenHandle, TokenInformationClass, buf, size.value, ctypes.byref(size)):
    raise ctypes.WinError()

# Step 4
array_length = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value

# safety-check: compares array_length (read-in) with array_length (calcuated)
# - comparison is performed in order to prevent over-reads
# - in case read-in memory (PrivilegeCount) is corrupted, returning invalid/larger size
#
# calculate size of memory for var-length array, after header/PrivilegeCount
# - size.value - ctypes.sizeof(wintypes.DWORD)
# --> size.value,   total size of buffer, allocated by GetTokenInformation()
# --> ctypes.sizeof(wintypes.DWORD),    size of first field PrivilegeCount (4-bytes)
#
# divide (//) memory for var-lengh array, by size of ONE array element
# returns how many array elements, can fit remaining buffer
# - // ctypes.sizeof(LUID_AND_ATTRIBUTES)

max_array_length = (size.value - ctypes.sizeof(wintypes.DWORD)) // ctypes.sizeof(LUID_AND_ATTRIBUTES)

if array_length > max_array_length:
    sys.exit(f"[!] Error: returned PrivilegeCount from GetTokenInformation() invalid")

# Step 5
TOKEN_PRIVILEGES = createStruct_tokenPrivileges(array_length)

# Step 6
token_privs = ctypes.cast(buf, ctypes.POINTER(TOKEN_PRIVILEGES)).contents


print(f"\n[+] Number of Privileges in Access Token: {token_privs.PrivilegeCount}")
print("--------------------------------------------")




# iterate through TOKEN_PRIVILEGES struct
for i in range(token_privs.PrivilegeCount):

    priv = token_privs.Privileges[i]
    priv_status = 'ENABLED' if (priv.Attributes & SE_PRIVILEGE_ENABLED) else 'DISABLED'

    # retrieve proper buffer size
    size_name = wintypes.DWORD()
    advapi32.LookupPrivilegeNameW(None, ctypes.byref(priv.Luid), None, ctypes.byref(size_name))

    # allocate proper-sized buffer
    lpName_buf = ctypes.create_unicode_buffer(size_name.value)

    # print result
    if not advapi32.LookupPrivilegeNameW(None, ctypes.byref(priv.Luid), lpName_buf, ctypes.byref(size_name)):
        print(f"[!] LookupPrivilegeNameW() Failed, LUID: ({priv.Luid.HighPart}, {priv.Luid.LowPart})")
        continue

    else:
        print(f"[{i}] {lpName_buf.value} -> {priv_status}\tLUID: ({priv.Luid.HighPart}, {priv.Luid.LowPart})")

        # increment on match, as for-loop will reset on each iteration if True/False







# func() to request which priv to flip
def ask_privilege():
    while True:
        try:
            i = int(input(f"\nEnter index of Privilege to flip [0-{token_privs.PrivilegeCount -1}]: "))

            if (0 <= i < token_privs.PrivilegeCount):
                return i
            else:
                print(f"[!] Please enter a valid index value")
                
        except ValueError as e:
            print(f"\n[!] Invalid Input, Error: {e}")



# Re-call privilege information from given index
def print_priv_to_flip(i):
    old_priv = token_privs.Privileges[i]
    old_priv_status = 'ENABLED' if (old_priv.Attributes & SE_PRIVILEGE_ENABLED) else 'DISABLED'

    # retrieve proper buffer size
    size_name = wintypes.DWORD()
    advapi32.LookupPrivilegeNameW(None, ctypes.byref(old_priv.Luid), None, ctypes.byref(size_name))

    # allocate proper-sized buffer
    lpName_buf = ctypes.create_unicode_buffer(size_name.value)

        # print result
    if not advapi32.LookupPrivilegeNameW(None, ctypes.byref(old_priv.Luid), lpName_buf, ctypes.byref(size_name)):
        print(f"[!] LookupPrivilegeNameW() Failed, LUID: ({old_priv.Luid.HighPart}, {old_priv.Luid.LowPart})")

    else:
        print(f"[{i}] {lpName_buf.value} -> {old_priv_status}\tLUID: ({old_priv.Luid.HighPart}, {old_priv.Luid.LowPart})")

        # returning human readable name
        # pevents having to re-iterate through buffer
        return lpName_buf.value


# ask for confirmation
def ask_confirmation():
    while True:
        response = input("\nConfirm privilege to flip ['y' or 'n']: ")
        ret = response.strip().lower()
        if ret in ('y', 'n'):
            return ret
        else:
            print("Please confirm privilege selection")



i = ask_privilege()
priv_name = print_priv_to_flip(i)   # save human-readable name
confirm = ask_confirmation()

if confirm == 'y':
    selected_priv = token_privs.Privileges[i]
else:
    sys.exit("[!] NOT FLIPPING")



##### AdjustTokenPrivileges() - advapi32.dll #####
##################################################
#
# Fip single chosen privilege
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges

# flip attribute - bitwise &
new_attr = SE_PRIVILEGE_DISABLED if (selected_priv.Attributes & SE_PRIVILEGE_ENABLED) else SE_PRIVILEGE_ENABLED

# create struct, and immediately instantiate class object -> (1)()
# - to handle TypeError being thrown when creating array of 1 element
tp = createStruct_tokenPrivileges(1)()
tp.PrivilegeCount = 1
tp.Privileges[0].Luid = selected_priv.Luid   # as Privileges is an array
tp.Privileges[0].Attributes = new_attr


# call AdjustTokenPrivileges()
if not advapi32.AdjustTokenPrivileges(
    TokenHandle, 
    False,
    ctypes.byref(tp),
    0,
    None,
    None
):
    raise ctypes.WinError(ctypes.get_last_error())


# verify - calling get_last_error()
# - not refering to return value of AdjustTokenPrivileges()
# - func() will return TRUE for following edge cases:
# ---- partially successful (eg, multiple privs in TOKEN_PRIVILEGES)
# ---- privilege not listed/assigned in Access Token
#
# above can occur for reasons such as elevation attempt on non-admin process
#
# TRUE return is for successful execution of function()
# - not about whether assignment occurred successfully
# - need to check ctypes.get_last_error() to verify successful assignment

error = ctypes.get_last_error()
if error == 0:
    print(f"[+] Successfully flipped privilege: {priv_name}")
elif error == 1300:
    print(f"[!] Error code: {error}, Privilege not held by token")
else:
    print(f"[!] Unexpected error, Code: {error}")


# Visual confirmation from calling GetTokenInformation() again
# - have to redo the whole process
# - AdjustTokenPrivileges() does not update local buffer (token_privs)

# Step 1
size = wintypes.DWORD() 
advapi32.GetTokenInformation(TokenHandle, TokenInformationClass, None, 0, ctypes.byref(size))

# Step 2
buf = ctypes.create_string_buffer(size.value) 

# Step 3
if not advapi32.GetTokenInformation(TokenHandle, TokenInformationClass, buf, size.value, ctypes.byref(size)):
    raise ctypes.WinError()

# Step 4
array_length = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value

# safety-check: compares array_length (read-in) with array_length (calcuated)
# - comparison is performed in order to prevent over-reads
# - in case read-in memory (PrivilegeCount) is corrupted, returning invalid/larger size
#
# calculate size of memory for var-length array, after header/PrivilegeCount
# - size.value - ctypes.sizeof(wintypes.DWORD)
# --> size.value,   total size of buffer, allocated by GetTokenInformation()
# --> ctypes.sizeof(wintypes.DWORD),    size of first field PrivilegeCount (4-bytes)
#
# divide (//) memory for var-lengh array, by size of ONE array element
# returns how many array elements, can fit remaining buffer
# - // ctypes.sizeof(LUID_AND_ATTRIBUTES)

max_array_length = (size.value - ctypes.sizeof(wintypes.DWORD)) // ctypes.sizeof(LUID_AND_ATTRIBUTES)

if array_length > max_array_length:
    sys.exit(f"[!] Error: returned PrivilegeCount from GetTokenInformation() invalid")

# Step 5
tp_new = createStruct_tokenPrivileges(array_length)

# Step 6
token_privs = ctypes.cast(buf, ctypes.POINTER(tp_new)).contents


print(f"\n[+] Number of Privileges in Access Token: {token_privs.PrivilegeCount}")
print("--------------------------------------------")




# iterate through TOKEN_PRIVILEGES struct
for i in range(token_privs.PrivilegeCount):

    priv = token_privs.Privileges[i]
    priv_status = 'ENABLED' if (priv.Attributes & SE_PRIVILEGE_ENABLED) else 'DISABLED'

    # retrieve proper buffer size
    size_name = wintypes.DWORD()
    advapi32.LookupPrivilegeNameW(None, ctypes.byref(priv.Luid), None, ctypes.byref(size_name))

    # allocate proper-sized buffer
    lpName_buf = ctypes.create_unicode_buffer(size_name.value)

    # print result
    if not advapi32.LookupPrivilegeNameW(None, ctypes.byref(priv.Luid), lpName_buf, ctypes.byref(size_name)):
        print(f"[!] LookupPrivilegeNameW() Failed, LUID: ({priv.Luid.HighPart}, {priv.Luid.LowPart})")
        continue

    else:
        print(f"[{i}] {lpName_buf.value} -> {priv_status}\tLUID: ({priv.Luid.HighPart}, {priv.Luid.LowPart})")



###################
##### Cleanup #####
###################
'''
print("\n[-] Closing opened handles:\n---------------------------")
close_handle(ProcessHandle, "Process")
close_handle(TokenHandle, "AccessToken")
'''
