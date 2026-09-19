@echo off
chcp 65001 >nul
title NetEye 安装向导
cd /d "%~dp0"

rem ============================================================
rem  NetEye 安装引导。
rem  真正的安装逻辑在 tools\neteye.py（Python 实现，不依赖 PATH
rem  里有没有 python / npm，会自动扫描常见安装位置）。
rem ============================================================

call "%~dp0tools\find_python.bat"

if not defined PY (
  echo.
  echo [X] 没有找到 Python 3.10 及以上的解释器。
  echo.
  echo     解决办法（任选其一）：
  echo       1^) 到 https://www.python.org/downloads/ 下载安装，
  echo          安装时勾选 "Add python.exe to PATH"
  echo       2^) 已经装了但不在 PATH 里，先执行下面这句再双击 install.bat：
  echo          set NETEYE_PYTHON=C:\完整路径\python.exe
  echo       3^) 直接指定解释器：
  echo          python tools\neteye.py install --python C:\完整路径\python.exe
  echo.
  pause
  exit /b 1
)

echo [*] 使用 Python: %PY%
echo.

rem ------------------------------------------------------------
rem  抓包驱动 Npcap 选择（默认勾选安装，用户可取消）
rem ------------------------------------------------------------
echo   ==========================================================
echo    [ 抓包驱动 Npcap ] 实时抓包必需，离线分析 pcap 不需要。
echo    安装包已内置 Npcap 1.89（默认勾选安装）。
echo    若本机已安装 Npcap 或不想安装，输入 n 取消。
echo   ==========================================================
set "NPCAP_CHOICE=Y"
set /p "NPCAP_CHOICE=是否安装 Npcap? [Y/n]（默认 Y）: "
if /I "%NPCAP_CHOICE%"=="n" (
  echo [*] 已选择跳过 Npcap 安装。
  "%PY%" "%~dp0tools\neteye.py" install --no-npcap %*
) else (
  echo [*] 将安装内置 Npcap（实时抓包必需）。
  "%PY%" "%~dp0tools\neteye.py" install %*
)
if errorlevel 1 (
  echo.
  echo [X] 安装未成功完成，请阅读上面的错误信息。
  pause
  exit /b 1
)

pause
