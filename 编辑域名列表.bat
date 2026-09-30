@echo off
set "DIR=%APPDATA%\QuickerPing"
if not exist "%DIR%" mkdir "%DIR%"
if not exist "%DIR%\hosts.txt" (
  echo google.com> "%DIR%\hosts.txt"
  echo github.com>> "%DIR%\hosts.txt"
)
start "" notepad "%DIR%\hosts.txt"
