cd /d %~dp0

msbuild WFRR.sln /p:Configuration=Debug /p:Platform=x64 /t:Clean,Build
msbuild WFRR.sln /p:Configuration=Release /p:Platform=x64 /t:Clean,Build
msbuild WFRR.sln /p:Configuration=Debug /p:Platform=x86 /t:Clean,Build
msbuild WFRR.sln /p:Configuration=Release /p:Platform=x86 /t:Clean,Build