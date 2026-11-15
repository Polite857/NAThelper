@echo off
rem ============================================================
rem  NAThelp9X build script -- Windows 95/98/Me ANSI target
rem  Toolchain : w64devkit (GCC, i686-w64-mingw32, msvcrt)
rem  Target    : Windows 95 / 98 / Me (all 32-bit)
rem  Usage     : build9x.bat           (release)
rem              build9x.bat clean     (delete outputs only)
rem ============================================================
setlocal enableextensions

set "HERE=%~dp0"
set "ROOT=%HERE%.."
set "GCC=%ROOT%\toolchain\w64devkit\bin\i686-w64-mingw32-gcc.exe"
set "SRC=%HERE%NAThelper.c"
set "EXE=%HERE%NAThelp9X.exe"
set "OBJ=%HERE%NAThelp9X.o"

if /i "%~1"=="clean" goto :clean
if not exist "%GCC%" (
  echo [ERROR] gcc not found: "%GCC%"
  exit /b 1
)

if not exist "%HERE%_build\tmp" mkdir "%HERE%_build\tmp"
set "TMP=%HERE%_build\tmp"
set "TEMP=%TMP%"

set "CFLAGS=-O2 -Wall -Wextra -Wno-unused-parameter -std=gnu99"
set "CFLAGS=%CFLAGS% -DNATHELPER_LEGACY=1 -DNATHELPER_ANSI=1 -DUNICODE -D_UNICODE"
set "CFLAGS=%CFLAGS% -D_WIN32_WINNT=0x0400 -DWINVER=0x0400"
set "CFLAGS=%CFLAGS% -finput-charset=UTF-8 -fexec-charset=UTF-8 -fwide-exec-charset=UTF-16LE"

rem subsystem 4.0: 95/98/Me loader accepts only <= 4.0 (same as NT4).
set "LDFLAGS=-mwindows -s -Wl,--major-subsystem-version,4,--minor-subsystem-version,0"
rem 9x kernel32/user32/gdi32 have no *W entry points (NAT_ANSI layer in source);
rem retail Win95 has no ws2_32.dll, so link Winsock 1.1 (wsock32.dll).
set "LIBS=-lwsock32 -lcomctl32 -lgdi32 -luser32 -ladvapi32 -lkernel32"

if exist "%EXE%" del /f /q "%EXE%" 2>nul
if exist "%EXE%" (
  echo [ERROR] cannot delete "%EXE%" - close NAThelp9X.exe first.
  exit /b 1
)

echo [1/2] compiling ...
"%GCC%" %CFLAGS% -c "%SRC%" -o "%OBJ%"
if errorlevel 1 goto :fail

echo [2/2] linking ...
"%GCC%" %OBJ% -o "%EXE%" %LDFLAGS% %LIBS%
if errorlevel 1 goto :fail

del /f /q "%OBJ%" 2>nul
echo.
echo [OK] %EXE%
for %%F in ("%EXE%") do echo      size = %%~zF bytes
echo      subsystem 4.0 (Windows 95 / 98 / Me)
exit /b 0

:fail
echo.
echo [FAILED] build aborted.
exit /b 1

:clean
if exist "%OBJ%" del /f /q "%OBJ%"
if exist "%EXE%" del /f /q "%EXE%"
echo [OK] cleaned
exit /b 0
