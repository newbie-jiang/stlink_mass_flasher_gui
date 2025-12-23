@echo off
setlocal

REM 进入 bat 所在目录（保证相对路径正确）
cd /d "%~dp0"

REM 用 python 启动（优先 python3，其次 python）
where python3 >nul 2>nul
if %errorlevel%==0 (
  python3 ".\stlink_mass_flasher_gui.py"
) else (
  python ".\stlink_mass_flasher_gui.py"
)

pause
endlocal
