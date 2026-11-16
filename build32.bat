@echo off
rem ============================================================
rem  NAThelp32 build script -- 32-bit / NT4-compatible target
rem  Toolchain : w64devkit (GCC, i686-w64-mingw32, msvcrt)
rem  Target    : Windows NT 4.0 SP5+ .. Windows 11 (x86)
rem  Usage     : build32.bat          (release)
rem              build32.bat clean    (delete outputs only)
rem ============================================================
setlocal enableextensions

set "HERE=%~dp0"
set "ROOT=%HERE%.."
set "GCC=%ROOT%\toolchain\w64devkit\bin\i686-w64-mingw32-gcc.exe"
set "SRC=%HERE%NAThelp32.c"
set "EXE=%HERE%NAThelp32.exe"
set "OBJ=%HERE%NAThelp32.o"

if /i "%~1"=="clean" goto :clean
if not exist "%GCC%" (
  echo [ERROR] gcc not found: "%GCC%"
  exit /b 1
)

if not exist "%HERE%_build\tmp" mkdir "%HERE%_build\tmp"
set "TMP=%HERE%_build\tmp"
set "TEMP=%TMP%"

set "CFLAGS=-O2 -Wall -Wextra -Wno-unused-parameter -std=gnu99"
rem NAThelp32.c 是 32 位专用源文件（含 NT4 兼容层，不含 9x 的 ANSI 层），
rem 不需要任何平台 -D，也不含条件编译。
set "CFLAGS=%CFLAGS% -DUNICODE -D_UNICODE"
set "CFLAGS=%CFLAGS% -finput-charset=UTF-8 -fexec-charset=UTF-8 -fwide-exec-charset=UTF-16LE"

rem subsystem 4.0: NT4 loader only accepts <= 4.0; newer systems still run it.
set "LDFLAGS=-mwindows -s -Wl,--major-subsystem-version,4,--minor-subsystem-version,0"
rem no iphlpapi: NT4 has no such DLL, gateway comes from the registry.
set "LIBS=-lws2_32 -lcomctl32 -lgdi32 -luser32 -ladvapi32 -lkernel32"

if exist "%EXE%" del /f /q "%EXE%" 2>nul
if exist "%EXE%" (
  echo [ERROR] cannot delete "%EXE%" - close NAThelp32.exe first.
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
echo      subsystem 4.0 (Windows NT 4.0 SP5+ / all 32-bit Windows)
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
