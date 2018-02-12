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

## V_REG.json Sample
```
{
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
```

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
