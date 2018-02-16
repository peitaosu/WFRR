# Windows Registry Redirection
[![GitHub license](https://img.shields.io/github/license/peitaosu/Win-Reg-Redirect.svg)](https://github.com/peitaosu/Win-Reg-Redirect/blob/master/LICENSE)

This project is supposed to redirect all registry calls of process to virtual registry.

## Requirements
* EasyHook

## Supported APIs
* RegOpenKey(Ex)
* RegCreateKey(Ex)
* RegDeleteKey(Ex)
* RegSetValue(Ex)
* RegQueryValue(Ex)
* RegCloseKey

## V_REG.json Sample
```
{
    "Keys": {
        "hkey_local_machine": {
            "Keys": {
                "software":{
                    "Keys": {
                        "microsoft": {
                            "Keys": {},
                            "Values": []
                        }
                    },
                    "Values": []
                }
            },
            "Values": [
                {
                    "Name": "value_name",
                    "Type": "REG_DWORD",
                    "Data": "0x00000001"
                }
            ]
        }
    }
}
```

## Usage

Please put `V_REG.json` in the same location as WinRegRedirector.exe.

```
WinRegRedirector ProcessID
                 ProcessName.exe
                 PathToExecutable

#example

> WinRegRedirector 1234
> WinRegRedirector notepad.exe
> WinRegRedirector C:\Windows\notepad.exe
```