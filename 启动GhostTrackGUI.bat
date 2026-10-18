@echo off
rem ============================================
rem  GhostTrack GUI v4 一键启动
rem  双击本文件即可启动程序
rem ============================================
chcp 65001 >nul 2>&1
cd /d "%~dp0"
where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw GhostTrackGUI.py
) else (
    start "" python GhostTrackGUI.py
)
