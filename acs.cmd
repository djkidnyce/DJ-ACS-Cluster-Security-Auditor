@echo off
rem Wrapper for acs_cli.js on Windows Command Prompt.
setlocal
where node >nul 2>nul
if errorlevel 1 (
  echo node is not on PATH. Node 18 or newer is required. 1>&2
  echo No Node available? The browser pages need no runtime at all: 1>&2
  echo   start "" "%~dp0dj_acs_auditor.html" 1>&2
  exit /b 2
)
node "%~dp0acs_cli.js" %*
