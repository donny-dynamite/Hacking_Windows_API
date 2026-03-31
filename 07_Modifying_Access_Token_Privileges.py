"""
Flip status of selected Privilege listed in access token
- ENABLED -> DISABLED and vice versa

Note: needs heavy re-factor
- currently just POC to prove code works, cleanup afterwards

Steps:
- PowerShell script to list PIDs, group-by ProcessName
- OpenProcess() for given PID
- OpenProcessToken() for returned process handle
- GetTokenInformation(TokenPrivileges)
- LookupPrivilegeNameW()
....
"""

#### REFACTOR IDEAS
# TOKEN_PRIVILEGES struct
# - def func() to specify length of LUID_AND_ATTRIBUTES array
#
# ARRAYS
# - ensure last element in ANY array has comma (standardise)
#
# LUID_AND_ATTRIBUTES
# - improve description, as Attributes is one of three int values
# - enabled / removeed / disabled
#
# Fix up the last half


import ctypes
from ctypes import wintypes
import subprocess
import sysad


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

PRIVILEGE_SET_ALL_NECESSARY = 0x01  # PRIVILEGE_SET()
SE_PRIVILEGE_ENABLED	    = 0X02  # LUID_AND_ATTRIBUTES()
SE_PRIVILEGE_DISABLED	    = 0X00  # LUID_AND_ATTRIBUTES()




######################################
##### Manually Packed Structures #####
######################################
#
# Following used for looking-up/checking process privs
# - LUID
# -	LUID_AND_ATTRIBUTES
#
# LUID is a 64-bit value, used here to identify privileges
# - two parts associated with lower/higher 32bits (LSB/MSB) of identifier
# - concat to return complete LUID > 0 if valid
#
# ie:
# if (LowPart == 0) and (HighPart == 0):
#     sys.exit(f"[!] Error, LUID not found")

class LUID(ctypes.Structure):
	_fields_ = [
	("LowPart",		wintypes.DWORD),
	("HighPart", 	wintypes.LONG)
	]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
	_fields_ = [
	("Luid", 		LUID),
	("Attributes", 	wintypes.DWORD)
	]




########################################
##### CloseHandle() - kernel32.dll #####
########################################
#
# For clean-up of open handles at the end of execution
# - actual HANDLE objects passed in from OpenProcess()
# - 'return wintypes.HANDLE(ret)' 
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle#return-value

# func() sigs
kernel32.CloseHandle.argtypes = [wintypes.HANDLE,]  # hObject
kernel32.CloseHandle.restype = wintypes.BOOL


# wrapper for CloseHandle()
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
# Return HANDLE to open process
# - force return type of HANDLE (c_void_p), otherwise ctypes converts to int
#
# This is done for easing Handle cleanup - CloseHandle()
# - ensures consistency when calling CloseHandle() multiple times
# - otherwise proc_handle passed as type 'int', and g_TokenHandle passed as HANDLE object
# - prevents needing to check type()/hasattr()/getattr() when calling CloseHandle()
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights

# func() sigs
kernel32.OpenProcess.argtypes = [
    wintypes.DWORD, # dwDesiredAccess
    wintypes.BOOL,  # bInheritHandle
    wintypes.DWORD, # dwProcessId
]
kernel32.OpenProcess.restype = wintypes.HANDLE

# def params
# PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_ALL_ACCESS = 0x1F0FFF # BitMask value
g_dwDesiredAccess = PROCESS_ALL_ACCESS
g_bInheritHandle = False
g_dwProcessId = pid_value


# func() wrapper for OpenProcess()
def open_proc(dwDesiredAccess, bInheritHandle, dwProcessId):
    ret = kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    if not ret:
        raise ctypes.WinError()    
    return wintypes.HANDLE(ret)


try:
    proc_handle = open_proc(g_dwDesiredAccess, g_bInheritHandle, g_dwProcessId)
    print(f"\n[+] OpenProcess() Successful, Process Handle: {proc_handle.value}")

except OSError as e:
    sys.exit(f"\n[!] OpenProcess() Failed. Error: {e}")




#############################################
##### OpenProcessToken() - advapi32.dll #####
#############################################
# 
# return Handle to Access Token ... or rather:
# - update Pointer var (TokenHandle) to contain a HANDLE, which refers to Access Token for given process
#
# Not defining the following:
# - g_ProcessHandle var, as proc_handle exists
# - OpenProcessToken() wrapper, as not returning any value, only updating g_TokenHandle in-place
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken#return-value

# func() sigs
advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE,                    # ProcessHandle
    wintypes.DWORD,                     # DesiredAccess
    ctypes.POINTER(wintypes.HANDLE),    # [o] TokenHandle
    ]
advapi32.OpenProcessToken.restype = wintypes.BOOL

# def params
g_DesiredAccess = 0xF01FF # BitMask for TOKEN_ALL_ACCESS
g_TokenHandle = wintypes.HANDLE()


try:
    if not advapi32.OpenProcessToken(proc_handle, g_DesiredAccess, ctypes.byref(g_TokenHandle)):
        raise ctypes.WinError()
    print(f"[+] OpenProcessToken() Successful, AccessToken Handle: {g_TokenHandle.value}")

except OSError as e:
    sys.exit(f"[!] OpenProcessToken() Failed, Error: {e}")




##################################################
##### LookupPrivilegeValueW() - advapi32.dll #####
##################################################
#
# Retrieve LUID (Locally Unique ID) for a specific privilege name
# - privileges are identified internally by LUIDs (not string names)
# - func() converts human-readable priv into LUID
# - eg from: SeDebugPrivilege -> to: LUID 
#
# Then included in struct, which is passed to PrivilegeCheck()
#
# NOTE: This func() does NOT check if priv exists in access token
# - only returns if there is a system LUID for a given privilege
#
# https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew#return-value

# func() sigs
advapi32.LookupPrivilegeValueW.argtypes = [
	wintypes.LPCWSTR,   			# lpSystemName (can be None)
	wintypes.LPCWSTR,				# lpName (eg "SeDebugPrivilege")
	ctypes.POINTER(LUID),	        # [o] lpLuid
]
advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL

# def params
g_lpSystemName = None
g_lpName = input("\nEnter privilege name (eg, SeDebugPrivilege): ") # case-insensitive
g_lpLuid = LUID()                       # instantiate LUID struct

try:
    if not advapi32.LookupPrivilegeValueW(g_lpSystemName, g_lpName, ctypes.byref(g_lpLuid)):
        raise ctypes.WinError()

    print(f"\n[+] LookupPrivilegeValueW() Sucscessful")
    print(f"Privilege exists on system: {g_lpName}", end=" ")
    print(f"-> LUID High: {g_lpLuid.HighPart}, LUID Low: {g_lpLuid.LowPart}")

except OSError as e:
    sys.exit(f"[!] LookupPrivilegeValueW() Failed, Error: {e}")




#################################################
##### LookupPrivilegeNameW() - advapi32.dll #####
#################################################
#
# Return human-readable name for given LUID
# - pre-defining, will be called in GetTokenInformation()
#
# Two params for name length
# - lpName, pointer to output buffer to receive priv name
#           memory where function writes the string
# - cchName, pointer to DWORD
#            tells Windows how large the buffer (lpName) is
#
# As size of data (cchName) is initially unknown, two calls will be made
# - first to retrieve actual buffer size
# - second, where both buffer size and size of data specified
# - similar to GetTokenInformation()
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegenamew

# func() sigs
advapi32.LookupPrivilegeNameW.argtypes = [
    wintypes.LPCWSTR,               # lpSystemName
    ctypes.POINTER(LUID),           # lpLuid
    wintypes.LPWSTR,                # [o] lpName (opt)
    ctypes.POINTER(wintypes.DWORD), # cchName (size)
]
advapi32.LookupPrivilegeNameW.restype = wintypes.BOOL




#################################################
##### GetTokenInformation () - advapi32.dll #####
#################################################
#
# Third argument passed to func():
# - [out, opt] LPVOID TokenInformation
# - from doco, "The structure put into this buffer, depends upon the TokenInformationClass"
# - struct type is not fixed, can be passed TOKEN_GROUPS, TOKEN_USER, TOKEN_OWNER etc
# - therefore defined as ctypes.c_void_p, not ctypes.POINTER()
#
# 

# Ref: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation

# func() sigs
advapi32.GetTokenInformation.argtypes = [
    wintypes.HANDLE,                # TokenHandle
    wintypes.INT,                   # TokenInformationClass
    ctypes.c_void_p,                # [o] TokenInformation (buffer) (opt)
    wintypes.DWORD,                 # TokenInformationLength
    ctypes.POINTER(wintypes.DWORD), # [o] ReturnLength
]
advapi32.GetTokenInformation.restype = wintypes.BOOL

# Specify information to retrieve from access token
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
TokenInformationClass = 3       # TokenPrivileges


###############################################################################
##### NOTE: this whole section will need a re-factor - for now it will do #####
###############################################################################

# GetTokenInformation() - cast struct with proper buffer size for variable-length array
# 
# Step 1 - retrieve proper buffer size, with first GetTokenInformation() call
# Step 2 - allocate proper-sized buffer variable
# Step 3 - retrieve full buffer, requesting TokenPrivileges class
# Step 4* - retrieve PrivilegeCount (length of array, which contain elements of LUID_AND_ATTRIBUTES)
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
advapi32.GetTokenInformation(g_TokenHandle, TokenInformationClass, None, 0, ctypes.byref(size))

# Step 2
buf = ctypes.create_string_buffer(size.value) 

# Step 3
if not advapi32.GetTokenInformation(g_TokenHandle, TokenInformationClass, buf, size.value, ctypes.byref(size)):
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
class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
    ("PrivilegeCount",  wintypes.DWORD),
    ("Privileges",      LUID_AND_ATTRIBUTES * array_length)
    ]

# Step 6
token_privs = ctypes.cast(buf, ctypes.POINTER(TOKEN_PRIVILEGES)).contents


print(f"\n[+] Number of Privileges in Access Token: {token_privs.PrivilegeCount}")
print("--------------------------------------------")


lookup_match = 0


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
        lookup_match += int(lpName_buf.value.lower() == g_lpName.lower())


if lookup_match:
    print(f"\n[+] Privilege match found in Access Token: {g_lpName}")
else:
    print(f"\n[!] Privilege match NOT found: {g_lpName}")









###################
##### Flip status
###################
#
# Steps:
# - print privilege based on index
# - ask for confirmation to flip
# - 
# 

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



# single-entry TOKEN_PRIVILEGES struct
# ref-factor this later
class TOKEN_PRIVILEGES_SINGLE(ctypes.Structure):
    _fields_ = [
    ("PrivilegeCount",  wintypes.DWORD),
    ("Privileges",      LUID_AND_ATTRIBUTES * 1),
    ]


##################################################
##### AdjustTokenPrivileges() - advapi32.dll #####
##################################################
#
# - currently only flipping a single privilege
#
#
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges

# func() sigs
advapi32.AdjustTokenPrivileges.argtypes = [
    wintypes.HANDLE,                    # TokenHandle
    wintypes.BOOL,                      # DisableAllPrivileges
    ctypes.POINTER(TOKEN_PRIVILEGES_SINGLE),   # NewState (opt)
    wintypes.DWORD,                     # BufferLength
    ctypes.POINTER(TOKEN_PRIVILEGES),   # PreviousState (opt)
    ctypes.POINTER(wintypes.DWORD),     # ReturnLength (opt)
]
advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL

# def params
DisableAllPrivileges = False


# Prepping new for TOKEN_PRIVILEGES instance
#
# flip state - bitwise operation
if selected_priv.Attributes & SE_PRIVILEGE_ENABLED:
    new_attr = SE_PRIVILEGE_DISABLED
else:
    new_attr = SE_PRIVILEGE_ENABLED



    
tp = TOKEN_PRIVILEGES_SINGLE()
tp.PrivilegeCount = 1
tp.Privileges[0].Luid = selected_priv.Luid   # as Privileges is an array
tp.Privileges[0].Attributes = new_attr


# call AdjustTokenPrivileges()
if not advapi32.AdjustTokenPrivileges(
    g_TokenHandle, 
    DisableAllPrivileges,
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
advapi32.GetTokenInformation(g_TokenHandle, TokenInformationClass, None, 0, ctypes.byref(size))

# Step 2
buf = ctypes.create_string_buffer(size.value) 

# Step 3
if not advapi32.GetTokenInformation(g_TokenHandle, TokenInformationClass, buf, size.value, ctypes.byref(size)):
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
class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
    ("PrivilegeCount",  wintypes.DWORD),
    ("Privileges",      LUID_AND_ATTRIBUTES * array_length)
    ]

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



###################
##### Cleanup #####
###################
'''
print("\n[-] Closing opened handles:\n---------------------------")
close_handle(proc_handle, "Process")
close_handle(g_TokenHandle, "AccessToken")
'''
