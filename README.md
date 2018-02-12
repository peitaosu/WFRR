# Windows Registry Redirection

## Requirements
* EasyHook

## Supported APIs
* RegOpenKey(Ex)
* RegCreateKey(Ex)
* RegDeleteKey(Ex)
* RegSetValue(Ex)
* RegQueryValue(Ex)
* RegCloseKey

## Usage
```
WinRegRedirector ProcessID
                 ProcessName.exe
                 PathToExecutable

#example

> WinRegRedirector 1234
> WinRegRedirector notepad.exe
> WinRegRedirector C:\Windows\notepad.exe
```
