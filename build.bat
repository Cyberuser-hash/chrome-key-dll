@echo off
setlocal

:: =============================================================================
:: chrome_key.dll standalone build (x64)
:: Run from a "x64 Native Tools Command Prompt" (VS Developer Command Prompt)
:: =============================================================================

set "CFLAGS=/nologo /W3 /WX- /O1 /Os /MT /GS- /Gy /GL /GR- /Gw /Zc:threadSafeInit- /std:c++17 /EHsc"
set "LFLAGS=/NOLOGO /LTCG /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT /INCREMENTAL:NO"

if not exist obj mkdir obj

echo [1/2] Compiling...
cl %CFLAGS% /c src\com\elevator.cpp    /Foobj\elevator.obj
if errorlevel 1 goto :fail
cl %CFLAGS% /c src\keydll\key_core.cpp /Foobj\key_core.obj
if errorlevel 1 goto :fail
cl %CFLAGS% /c src\keydll\key_api.cpp  /Foobj\key_api.obj
if errorlevel 1 goto :fail

echo [2/2] Linking chrome_key.dll...
link %LFLAGS% /DLL /OUT:chrome_key.dll /IMPLIB:chrome_key.lib ^
    obj\elevator.obj obj\key_core.obj obj\key_api.obj ^
    ole32.lib oleaut32.lib crypt32.lib shell32.lib advapi32.lib
if errorlevel 1 goto :fail

del /q obj\*.obj 2>nul
rmdir obj 2>nul
echo.
echo [+] Build Complete: chrome_key.dll
goto :eof

:fail
echo [-] Build failed.
exit /b 1
