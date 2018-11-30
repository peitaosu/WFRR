@echo off

cd /d %~dp0

if ".%ZIP_TOOL%"=="." echo "Please set %%ZIP_TOOL%% with your 7za.exe location." & goto :eof

FOR /F "tokens=2 delims==" %%a in ('
    wmic datafile where name^="%cd:\=\\%\\bin\\x64\\Debug\\WFRR.exe" get Version /value 
') do set "WFRR_VER=%%a"

%ZIP_TOOL% a .\bin\WFRR_v%WFRR_VER%_x64_debug.zip .\bin\x64\Debug\*
%ZIP_TOOL% a .\bin\WFRR_v%WFRR_VER%_x64_release.zip .\bin\x64\Release\*
%ZIP_TOOL% a .\bin\WFRR_v%WFRR_VER%_x86_debug.zip .\bin\x86\Debug\*
%ZIP_TOOL% a .\bin\WFRR_v%WFRR_VER%_x86_release.zip .\bin\x86\Release\*
