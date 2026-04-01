"""
Flip status of selected Privilege listed in access token
- ENABLED -> DISABLED and vice versa
"""


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

# GetTokenInformation()
TokenInformationClass = 3       # TokenPrivileges



###################
##### STRUCTS #####
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
def tokenPrivileges_createStruct(length):
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
    wintypes.LPVOID,                  # [o] TokenInformation (buffer) (opt)
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
    ctypes.c_void_p,                    # NewState (new TOKEN_PRIVILEGES struct) (opt)
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
        raise ctypes.WinError(ctypes.get_last_error())    
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
        raise ctypes.WinError(ctypes.get_last_error())
    print(f"[+] OpenProcessToken() Successful, AccessToken Handle: {TokenHandle.value}")

except OSError as e:
    sys.exit(f"[!] OpenProcessToken() Failed, Error: {e}")




################################################
##### GetTokenInformation() - advapi32.dll #####
################################################
#
# two-call method to return TokenPrivileges information for Access Token
#
# first step:
# - first call: TokenInformation = NULL, TokenInformationLength = 0
# - call fails with ERROR_INSUFFICIENT_BUFFER -> ReturnLength returned
# - allocate buf of required size (ReturnLength -> TokenInformationLength)
#
# second step:
# - re-call with pointer to buffer, and 

def get_token_info_buffer(TokenHandle, TokenInformationClass):
    
    size = wintypes.DWORD(0) 

    # first step: retrieve ReturnLength
    advapi32.GetTokenInformation(TokenHandle, TokenInformationClass, None, 0, ctypes.byref(size))

    buf = ctypes.create_string_buffer(size.value) 

    # second step: re-call, with buffer and correct sizes
    if not advapi32.GetTokenInformation(TokenHandle, TokenInformationClass, buf, size.value, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())

    return buf, size.value




##### Cast TOKEN_PRIVILEGES struct
#
# directly cast buf to DWORD to retrieve length of array (PrivilegeCount)
# - avoids casting to struct twice, as info sites in first DWORD/4-bytes
 
# - buf memory layout already known (by struct definition)
# [DWORD PrivilegeCount]
# [LUID_AND_ATTRIBUTES #1]
# [LUID_AND_ATTRIBUTES #2]
# [LUID_AND_ATTRIBUTES #n]
#
# Safety check implemented - prevent memory over read
# - ensure memory-read (ReturnLength) !> actual memory left in buffer
#
# - size_payload == size of buffer after header/DWORD
# - integer division (//) for var-lengh array, by size of ONE array element
# - returns how many array elements, can fit remaining buffer

def cast_token_privileges(buf, size):

    array_length = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value

    # calculate max len(array) from remaining buffer space
    size_payload = (size - ctypes.sizeof(wintypes.DWORD))
    size_single_element = ctypes.sizeof(LUID_AND_ATTRIBUTES)
    max_array_length = size_payload // size_single_element

    # safety check
    if array_length > max_array_length:
        sys.exit(f"[!] Error: returned PrivilegeCount from GetTokenInformation() invalid")

    TOKEN_PRIVILEGES = tokenPrivileges_createStruct(array_length)

    return ctypes.cast(buf, ctypes.POINTER(TOKEN_PRIVILEGES)).contents




#############################################
##### Print TokenInformation Privileges #####
#############################################
# NOTE: may not need to return list here
# - tokenPrivileges_requestFlip -> returns TOKEN_PRIVILEGES object
# - returns single object that can be referenced directly

def tokenPrivileges_printInfo(token_privs, index=None, Flipped=False):

    # which message to print
    if Flipped == False:
        if index == None:
            print(f"\n[+] Privileges in Access Token: {token_privs.PrivilegeCount}")
            print("--------------------------------")
        else:
            print("\n[+] Selected Privilege in Access Token:")
            print("-----------------------------------------")
    
    else:
        print("-------------------------------------------------")


    # which indices to iterate
    indices = range(token_privs.PrivilegeCount) if index is None else [index]


    # iterate through TOKEN_PRIVILEGES struct
    for i in indices:

        priv = token_privs.Privileges[i]
        priv_status = 'ENABLED' if (priv.Attributes & SE_PRIVILEGE_ENABLED) else 'DISABLED'

        # retrieve/allocate proper buffer size
        size = wintypes.DWORD(0)
        advapi32.LookupPrivilegeNameW(None, ctypes.byref(priv.Luid), None, ctypes.byref(size))
        lpName = ctypes.create_unicode_buffer(size.value)

        # print result
        if advapi32.LookupPrivilegeNameW(None, ctypes.byref(priv.Luid), lpName, ctypes.byref(size)):
            print(f"[{i}] {lpName.value:40} -> {priv_status:20}\tLUID: ({priv.Luid.HighPart}, {priv.Luid.LowPart})")

        else:
            print(f"[!] LookupPrivilegeNameW() Failed, LUID: ({priv.Luid.HighPart}, {priv.Luid.LowPart})")
            continue




#####################################
##### Request Privilege to flip #####
#####################################
#
# Only one choice of Privilege given to flip, eg ENABLED -> DISABLED

def tokenPrivileges_requestFlip(token_privs):
    
    while True:
        try:
            i = int(input(f"\nEnter index of Privilege to flip status [0-{token_privs.PrivilegeCount -1}]: "))

            if (0 <= i < token_privs.PrivilegeCount):
                # return info from single element in array
                # this is the LUID_AND_ATTRIBUTES nested struct, with Luid and Attributes fields
                return i, token_privs.Privileges[i]
            else:
                print(f"[!] Please enter a valid index value")
                
        except ValueError as e:
            print(f"\n[!] Invalid Input, Error: {e}")




##################################################
##### AdjustTokenPrivileges() - advapi32.dll #####
##################################################
#
# Fip status of chosen privilege, between ENABLED -> DISABLED -> ENABLED

def tokenPrivileges_flipAttribute(TokenHandle, selected_priv):
    
    # flip attribute - bitwise &
    new_attr = SE_PRIVILEGE_DISABLED if (selected_priv.Attributes & SE_PRIVILEGE_ENABLED) else SE_PRIVILEGE_ENABLED

    # immediately instantiate new struct/class object, with array[1] -> (1)()
    # - to handle TypeError being thrown when creating array of 1 element
    tp = tokenPrivileges_createStruct(1)()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = selected_priv.Luid   # as Privileges is an array
    tp.Privileges[0].Attributes = new_attr


    if not advapi32.AdjustTokenPrivileges(
        TokenHandle,        # TokenHandle
        False,              # DisableAllPrivileges
        ctypes.byref(tp),   # NewState (TOKEN_PRIVILEGES struct) (opt)
        0,                  # BufferLength
        None,               # [o] PreviousState (opt)
        None                # [o] ReturnLength (opt)
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    # function returns TRUE upon successful execution of function
    # - NOT whether assignment occurred successfully
    # - need to check ctypes.get_last_error() to verify successful assignment

    ctypes.set_last_error(0)        # clear out any stale errors
    error = ctypes.get_last_error()
    if error == 0:
        print(f"\n[+] Successfully flipped privilege, LUID: {selected_priv.Luid.HighPart, selected_priv.Luid.LowPart}")
    elif error == 1300:
        print(f"\n[!] Error code: {error}, Privilege not held by token")
    else:
        print(f"\n[!] Unexpected error, Code: {error}")



##########################
##### Function Calls #####
##########################
#
# Steps:
#
# Privilege Information - RETRIEVE:
# - retrieve TokenPrivileges buffer from Access Token
# - cast buffer onto new TOKEN_PRIVILEGES struct
#
# Privilege Information - PRINT
# - print all privileges
# - choose which single-privilege to flip
# - print single-privilege to be flipped
#
# Privilege Information - FLIP
# - flip privilege
#
# Privilege Information - RETRIEVE (repeat)
# - retrieve updated TokenPrivileges buffer from Access Token
# - cast buffer onto new TOKEN_PRIVILEGES struct
# - print single-privilege again, confirm that it was flipped


##### Privilege Information -> RETRIEVE #####
buf, size = get_token_info_buffer(TokenHandle, TokenInformationClass)
tokenPrivileges_full = cast_token_privileges(buf, size)


##### Privilege Information -> PRINT #####
# Print all privilege information
tokenPrivileges_printInfo(tokenPrivileges_full)

# Request which privilege to flip
# - return int, and single LUID_AND_ATTRIBUTES struct
tokenPrivileges_index, tokenPrivileges_object = tokenPrivileges_requestFlip(tokenPrivileges_full)

# Re-print information for single privilege, given index
tokenPrivileges_printInfo(tokenPrivileges_full, tokenPrivileges_index)


##### Privilege Information -> FLIP #####
# Flip chosen privilege
tokenPrivileges_flipAttribute(TokenHandle, tokenPrivileges_object)

##### Privilege Information - RETRIEVE (repeat)
# Re-retrieve TokenInformation buffer from Access Token (fresh copy)
buf_new, size_new = get_token_info_buffer(TokenHandle, TokenInformationClass)

# Cast buffer onto new TOKEN_PRIVILEGES struct
tokenPrivileges_full_new = cast_token_privileges(buf_new, size_new)

# Print single-privilege again
tokenPrivileges_printInfo(tokenPrivileges_full_new, tokenPrivileges_index, Flipped=True)




###################
##### Cleanup #####
###################

print("\n[-] Closing opened handles:\n---------------------------")
close_handle(ProcessHandle, "Process")
close_handle(TokenHandle, "AccessToken")
