@echo off
setlocal
title Backup Monitor Agent Legacy - Windows Server 2012
cd /d "%~dp0"

echo.
echo Backup Monitor Agent Legacy - Windows Server 2012
echo =================================================
echo.
echo Este instalador usa console, sem tela grafica, para ser mais compativel.
echo Execute como Administrador.
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-legacy-ws2012.ps1" -RunNow

echo.
if errorlevel 1 (
  echo FALHOU. Confira o log:
  echo %TEMP%\backup-monitor-agent-install-legacy.log
) else (
  echo Concluido.
)
echo.
pause
