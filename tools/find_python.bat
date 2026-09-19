@echo off
rem ============================================================
rem  定位一个可运行的 python.exe，结果写入变量 PY。
rem  用法： call "%~dp0find_python.bat"
rem  只负责"找到一个能跑 tools\neteye.py 的解释器"，
rem  版本是否 >=3.10、依赖是否齐全由 neteye.py 负责判断。
rem ============================================================

set "PY="

rem 1) 用户显式指定
if defined NETEYE_PYTHON if exist "%NETEYE_PYTHON%" set "PY=%NETEYE_PYTHON%"

rem 2) 项目自带虚拟环境
if not defined PY if exist "%~dp0..\.venv\Scripts\python.exe" set "PY=%~dp0..\.venv\Scripts\python.exe"

rem 3) WorkBuddy 托管版本（目录按版本号升序，后写入者版本最高）
if not defined PY (
  for /d %%d in ("%USERPROFILE%\.workbuddy\binaries\python\versions\*") do (
    if exist "%%d\python.exe" set "PY=%%d\python.exe"
  )
)
if not defined PY (
  for /d %%d in ("%USERPROFILE%\.workbuddy\binaries\python\envs\*") do (
    if exist "%%d\Scripts\python.exe" set "PY=%%d\Scripts\python.exe"
  )
)

rem 4) 官方安装器的默认位置
if not defined PY (
  for /d %%d in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
    if exist "%%d\python.exe" set "PY=%%d\python.exe"
  )
)
if not defined PY (
  for /d %%d in ("C:\Python3*") do (
    if exist "%%d\python.exe" set "PY=%%d\python.exe"
  )
)

rem 5) py 启动器
if not defined PY (
  where py >nul 2>nul
  if not errorlevel 1 (
    for /f "usebackq delims=" %%i in (`py -3 -c "import sys;print(sys.executable)"`) do (
      if not defined PY set "PY=%%i"
    )
  )
)

rem 6) PATH 里的 python（跳过 Microsoft Store 的占位程序）
if not defined PY (
  where python >nul 2>nul
  if not errorlevel 1 (
    for /f "usebackq delims=" %%i in (`python -c "import sys;print(sys.executable)"`) do (
      if defined PY goto :fp_done
      echo %%i | findstr /I /C:"WindowsApps" >nul
      if not errorlevel 1 goto :fp_done
      set "PY=%%i"
    )
  )
)

:fp_done
exit /b 0
