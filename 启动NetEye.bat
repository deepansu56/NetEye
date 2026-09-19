@echo off
chcp 65001 >nul
title NetEye 启动器
cd /d "%~dp0"

rem ============================================================
rem  NetEye 启动引导。
rem  真正的启动逻辑在 tools\neteye.py start（自动提权、自动探测
rem  Python、检测端口占用、自动打开浏览器）。
rem ============================================================

rem ---- 需要管理员权限才能抓包；只请求一次，避免循环提权 ----
net session >nul 2>nul
if not errorlevel 1 goto :has_admin

if /I "%1"=="--elevated" (
  echo [!] 提权未成功（UAC 被取消或账户受限），以普通权限继续。
  echo     普通权限下实时抓包可能不可用，离线分析 pcap 不受影响。
  echo.
  goto :has_admin
)

echo [!] 当前不是管理员权限，正在请求提权（实时抓包需要驱动权限）...
echo.
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '--elevated' -Verb RunAs"
exit /b 0

:has_admin

call "%~dp0tools\find_python.bat"

if not defined PY (
  echo.
  echo [X] 没有找到 Python 3.10 及以上的解释器，请先双击 install.bat 完成安装。
  echo     若已安装但不在 PATH 里，先执行：set NETEYE_PYTHON=C:\完整路径\python.exe
  echo.
  pause
  exit /b 1
)

"%PY%" "%~dp0tools\neteye.py" start %*
if errorlevel 1 (
  echo.
  echo [X] 启动未成功完成，请阅读上面的错误信息。
  pause
  exit /b 1
)

pause
