# Windows File/Registry Redirection
[![GitHub license](https://img.shields.io/github/license/peitaosu/Win-FS-Reg-Redirect.svg)](https://github.com/peitaosu/Win-FS-Reg-Redirect/blob/master/LICENSE)

This project is supposed to redirect all file/registry calls of process to virtual file system/registry.

## Requirements
- WFRR.exe
   * EasyHook 
   * Newtonsoft.Json
   * NDesk.Options
   ```
   nuget restore WFRR.sln
   ```
- Reg2JSON.py
   * python 2.x

## Supported APIs
* RegOpenKey(Ex)
* RegCreateKey(Ex)
* RegDeleteKey(Ex)
* CreateFileW
* DeleteFileW
* CopyFileW

## Build
* .NET 4.5.2+/VS2015+
    ```
    # In MSBuild Command Prompt for VS2015/VS2017 #
    
    >.\Build.bat
    ```

## V_REG.json Sample
* Source: source registry path.
* Destination: target registry path which you want to redirect to.
```
{
    "Mapping": [
        {
            "Source": "",
            "Destination": ""
        },
        {
            "Source": "",
            "Destination": ""
        }
    ],
    "VRegRedirected": ""
}
```

## V_FS.json Sample
* Source: source directory path.
* Destination: target directory path which you want to redirect to.
```
{
    "Mapping": [
        {
            "Source": "",
            "Destination": ""
        },
        {
            "Source": "",
            "Destination": ""
        }
    ]
}
```


## Usage

Please put `V_REG.json` and `V_FS.json` in the same location as WFRR.exe.

```
Usage: WFRR.exe [OPTIONS]

Options:
  -e, --exe=VALUE            the executable file to launch and inject.
  -a, --arg=VALUE            the arguments of executable file to launch and
                               inject.
  -n, --pname=VALUE          the name of process want to inject.
  -i, --pid=VALUE            the id of process want to inject.
      --all                  inject file hook and registry hook.
      --file                 inject file hook only.
      --reg                  inject registry hook only.
  -h, --help                 show help messages
```


## Tool - VREG.py

`VREG.py` is the tool help you create a reg file based on your original reg file and `V_REG.json` configuration.

```
Usage: VREG.py [options]

Options:
  -h, --help            show this help message and exit
  -i IN_REG, --in=IN_REG
                        *.reg file to input
  -o OUT_REG, --out=OUT_REG
                        *.reg file to output
  -c CONFIG, --cfg=CONFIG
                        V_REG.json to input
  --32bit               is your application 32bit?
```

## How To Debug

Current supported Hooks may be not covered all File System/Registry operations. You probably need to implement additional hooks to cover them.
To know which API calls haven't be hooked, process monitor is your good friend to monitor program operations.