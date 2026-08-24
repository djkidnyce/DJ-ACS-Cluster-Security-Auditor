@echo off
rem Wrapper for acs_cli.js on Windows Command Prompt.
setlocal
where node >nul 2>nul
if errorlevel 1 (
  echo node is not on PATH. acs_cli.js needs Node 18 or newer. 1>&2
  echo. 1>&2
  echo If Node cannot be installed here, the page needs no runtime at all and 1>&2
  echo covers everything except headless CI: scoring, violations, fix routes, 1>&2
  echo drafted YAML and the full report. 1>&2
  echo   start "" "%~dp0dj_acs_auditor.html" 1>&2
  echo. 1>&2
  echo With a container runtime the CLI runs without installing Node: 1>&2
  echo   podman run --rm -v "%~dp0:/w" -w /w docker.io/library/node:20-alpine node acs_cli.js --help 1>&2
  exit /b 2
)
node "%~dp0acs_cli.js" %*
