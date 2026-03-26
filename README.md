# Hacking the Windows API with Python
Notes from Brandon Dennis's course - Hacking the Windows API with Python (Udemy)

**Observed Caveats:**

Possibly due to age of course content, there are a few observed 'discrepencies' with the course content, and attempting to do the following on a 'modern' Windows 11 machine. 

Things to look out for:

[+] When deciding between ```ApiFunctionA()``` vs ```ApiFunctionW()```, its likely simpler to choose the Unicode variant ```W``` vs the ANSI variant ```A```, as this prevents needing to re-encode string values to utf-8.

[+] Complete hex values don't specifically need to be fully copied from doco, eg when specifying uType for MessageBoxW(). To display the OK/Cancel buttons in a message box, in doco the value is ```0x00000001```, however shortened hex ```0x1``` or the integer value ```1``` can also be passed

[+] For ```OpenProcess()```, doco describes the return type as "the return value is an open handle to the specified process." However in Python, ctypes may show it as an int or object depending on whether it’s **_returned_** or **_preallocated_**. 

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

**ALL OF THIS IS TO SAY, IF YOU ARE EXPECTING YOUR RETURN TYPE TO BE OF ```ctypes.c_void_p``` (HANDLE), AND YOU RECEIVE AN 'INT', THIS IS THE REASON WHY**
