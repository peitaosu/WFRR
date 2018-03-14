# Windows Registry Redirection
[![GitHub license](https://img.shields.io/github/license/peitaosu/Win-Reg-Redirect.svg)](https://github.com/peitaosu/Win-Reg-Redirect/blob/master/LICENSE)

This project is supposed to redirect all registry calls of process to virtual registry.

## Requirements
- WinRegRedirector.exe - use NuGet Package Manager to install these dependencies for project
   * EasyHook 
   * Newtonsoft.Json
- Reg2JSON.py
   * python 2.x

## Supported APIs
* RegOpenKey(Ex)
* RegCreateKey(Ex)
* RegDeleteKey(Ex)
* RegSetValue(Ex)
* RegQueryValue(Ex)
* RegCloseKey

## V_REG.json Sample
* Keys: please use the key name with lower case.
* Values: support REG_DWORD, REG_QWORD, REG_SZ and REG_BINARY types.
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
WinRegRedirector.exe ProcessID
                     ProcessName.exe
                     PathToExecutable

#example

> WinRegRedirector.exe 1234
> WinRegRedirector.exe notepad.exe
> WinRegRedirector.exe C:\Windows\notepad.exe
```

## Convert V_REG.json from .reg file

```
> python Tool\Reg2JSON.py in.reg out.json

# suppose the in.reg is using utf-16, if not, please change the encoding in get_reg_str_list()
```