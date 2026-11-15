@echo off
rem ============================================================
rem  NAThelper build script
rem  Toolchain : w64devkit (GCC, x86_64-w64-mingw32, msvcrt)
rem  Target    : Windows Vista SP2 x64  (subsystem 6.0)
rem  Usage     : build.bat            (release)
rem              build.bat clean      (delete outputs only)
rem ============================================================
setlocal enableextensions

set "HERE=%~dp0"
set "ROOT=%HERE%.."
set "GCC=%ROOT%\toolchain\w64devkit\bin\gcc.exe"
set "SRC=%HERE%NAThelper.c"
set "EXE=%HERE%NAThelper.exe"
set "OBJ=%HERE%NAThelper.o"

if /i "%~1"=="clean" goto :clean
if not exist "%GCC%" (
  echo [ERROR] gcc not found: "%GCC%"
  echo         Extract w64devkit into "%ROOT%\toolchain\w64devkit".
  exit /b 1
)

rem gcc needs a writable temp dir; use a project-local one to avoid
rem "Cannot create temporary file" failures on locked-down %TEMP%.
if not exist "%HERE%_build\tmp" mkdir "%HERE%_build\tmp"
set "TMP=%HERE%_build\tmp"
set "TEMP=%TMP%"

set "CFLAGS=-O2 -Wall -Wextra -Wno-unused-parameter -std=gnu99"
set "CFLAGS=%CFLAGS% -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0600 -DWINVER=0x0600"
set "CFLAGS=%CFLAGS% -finput-charset=UTF-8 -fexec-charset=UTF-8 -fwide-exec-charset=UTF-16LE"

set "LDFLAGS=-mwindows -s -Wl,--major-subsystem-version,6,--minor-subsystem-version,0"
set "LIBS=-lws2_32 -liphlpapi -lcomctl32 -lgdi32 -luser32 -lkernel32"

if exist "%EXE%" del /f /q "%EXE%" 2>nul
if exist "%EXE%" (
  echo [ERROR] cannot delete "%EXE%" - close NAThelper.exe first.
  exit /b 1
)

echo [1/2] compiling ...
"%GCC%" %CFLAGS% -c "%SRC%" -o "%OBJ%"
if errorlevel 1 goto :fail

echo [2/2] linking ...
"%GCC%" %OBJ% -o "%EXE%" %LDFLAGS% %LIBS%
if errorlevel 1 goto :fail

rem Drop the intermediate object; the exe is the only artefact.
del /f /q "%OBJ%" 2>nul

echo.
echo [OK] %EXE%
for %%F in ("%EXE%") do echo      size = %%~zF bytes
echo      subsystem 6.0 (Windows Vista SP2 x64 or later)
exit /b 0

:fail
echo.
echo [FAILED] build aborted.
exit /b 1

:clean
if exist "%OBJ%" del /f /q "%OBJ%"
if exist "%EXE%" del /f /q "%EXE%"
if exist "%HERE%_build" rmdir /s /q "%HERE%_build"
echo [OK] cleaned
exit /b 0
