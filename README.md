# Hacking the Windows API with Python
Notes from Brandon Dennis's course - Hacking the Windows API with Python (Udemy)

<br><br><br>

**Observed Caveats:**

Possibly due to age of course content, there are a few observed 'discrepencies' with the course content, and attempting to do the following on a 'modern' Windows 11 machine. 

<br>

Things to look out for:

**[+]** When deciding between ```ApiFunctionA()``` vs ```ApiFunctionW()```, its likely simpler to choose the Unicode variant ```W``` vs the ANSI variant ```A```, as this prevents needing to re-encode string values to utf-8.

<br>

**[+]** Complete hex values don't specifically need to be fully copied from doco, eg when specifying uType for MessageBoxW(). To display the OK/Cancel buttons in a message box, in doco the value is ```0x00000001```, however shortened hex ```0x1``` or the integer value ```1``` can also be passed

<br>

**[+]** For ```OpenProcess()```, doco describes the return type as "the return value is an open handle to the specified process." However in Python, ctypes may show it as an int or object depending on whether it’s **_returned_** or **_preallocated_**. 

eg, returned:
```
> ret = OpenProcess()
> type(ret)
<class 'int'>
```

This return-type-of-int will still occur even when explicitly specifying the return type in the function signature, eg:
```
# explicitly specify return type of OpenProcess()
> kernel32.OpenProcess.restype = wintypes.HANDLE
```

A _preallocated_ example would be ```OpenProcessToken()```, where it takes as an argument, a pointer to a variable that can receive a handle, eg:
```
# pre-allocating a variable that can store a windows HANDLE
> TokenHandle = wintypes.HANDLE()
```

Then a pointer to this variable is passed to ```OpenProcessToken()```, to which the value of the HANDLE is written to:
```
# Passing in a pointer to TokenHandle, via ctypes.byref()
> OpenProcessToken(..., ctypes.byref(TokenHandle))
```

The TokenHandle variable itself will still be of type ```ctypes.c_void_p```
```
> type(TokenHandle)
<class 'ctypes.c_void_p'>
```

And the actual value of the HANDLE can be seen via ```TokenHandle.value``` or ```print(TokenHandle)```

To explicitly force the return type to be of type HANDLE (c_void_p), then return the following
```
> return wintypes.HANDLE(ret)
```

**ALL OF THIS IS TO SAY, IF YOU ARE EXPECTING YOUR RETURN TYPE TO BE OF ```ctypes.c_void_p``` (HANDLE), AND YOU RECEIVE AN 'INT', THIS IS THE REASON WHY**

<br>

**[+]** ```OpenProcessToken()``` via ```kernel32.dll``` or ```advapi32.dll```

Course content shows ```kernel32.OpenProcessToken()``` calls
- however MS Doco shows ```OpenProcessToken()``` as part of advapi32.dll

Inspecting ```kernel32.dll``` in 'Dependencies' (OS fork of Dependency Walker) shows following
- export icon as ```C->``` indicating forwarded function call
- ```VirtualAddress``` column as ```api-ms-win-core-processthreads-11-1-0.OpenProcessToken```
- indicates API Set DLL usage, to abstract actual .dll call for exported functions
- inspecting ```advapi32.dll``` shows ```OpenProcessToken()``` export
- likely path: kernel32.dll -> api-ms-win-core-processthreads-* -> advapi32.dll

In short, ```kernel32.OpenProcessToken()``` works but due to implementing API forwarding
