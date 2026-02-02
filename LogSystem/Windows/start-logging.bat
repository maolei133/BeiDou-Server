@echo off
setlocal EnableDelayedExpansion
chcp 65001
title 北斗服务端日志系统

rem --- 1. 确定基础目录 ---
set "BASE_DIR=%~dp0"
if "%BASE_DIR:~-1%"=="\" set "BASE_DIR=%BASE_DIR:~0,-1%"
cd /d "%BASE_DIR%"

echo [日志系统] 基础目录: %BASE_DIR%

rem --- 2. 目录检查与创建 ---
if not exist "bin" mkdir "bin"
if not exist "config" mkdir "config"
if not exist "download" mkdir "download"
if not exist "log" mkdir "log"

rem --- 3. 读取并验证旧状态 ---
set "RUNTIME_CONFIG=config\runtime.ini"
set "LOKI_PID=0"
set "PROMTAIL_PID=0"
set "LAST_PATH="

if exist "%RUNTIME_CONFIG%" (
    for /f "usebackq tokens=1* delims==" %%a in ("%RUNTIME_CONFIG%") do (
        set "key=%%a"
        set "val=%%b"
        set "key=!key: =!"

        if /i "!key!"=="LokiPID" set "LOKI_PID=!val!"
        if /i "!key!"=="PromtailPID" set "PROMTAIL_PID=!val!"
        if /i "!key!"=="LastPath" set "LAST_PATH=!val!"
    )
)

rem 强制数值清洗 PID
set /a "LOKI_PID_NUM=LOKI_PID" 2>nul
set "LOKI_PID=%LOKI_PID_NUM%"
set /a "PROMTAIL_PID_NUM=PROMTAIL_PID" 2>nul
set "PROMTAIL_PID=%PROMTAIL_PID_NUM%"

rem 检查存活状态
set "LOKI_ALIVE=0"
set "PROMTAIL_ALIVE=0"

if %LOKI_PID% GTR 0 (
    tasklist /FI "PID eq %LOKI_PID%" 2>NUL | find /I "%LOKI_PID%" >NUL
    if not errorlevel 1 set "LOKI_ALIVE=1"
)
if %PROMTAIL_PID% GTR 0 (
    tasklist /FI "PID eq %PROMTAIL_PID%" 2>NUL | find /I "%PROMTAIL_PID%" >NUL
    if not errorlevel 1 set "PROMTAIL_ALIVE=1"
)

echo [状态] Loki: %LOKI_ALIVE%, Promtail: %PROMTAIL_ALIVE%

rem --- 4. 决策逻辑 ---

rem 如果两者都存活，直接退出
if "%LOKI_ALIVE%"=="1" if "%PROMTAIL_ALIVE%"=="1" (
    echo [提示] 日志系统已在后台正常运行。

    echo [提示] 3秒后自动关闭此窗口...
    timeout /t 3 >nul
    exit
)

rem 如果状态不完整（一个活一个死），清理旧环境
if "%LOKI_ALIVE%"=="1" (
    echo [修复] 发现 Loki 残留进程，正在清理...
    taskkill /F /PID %LOKI_PID% >nul 2>&1
)
if "%PROMTAIL_ALIVE%"=="1" (
    echo [修复] 发现 Promtail 残留进程，正在清理...
    taskkill /F /PID %PROMTAIL_PID% >nul 2>&1
)

rem 兜底清理僵尸进程
taskkill /F /IM loki-windows-amd64.exe >nul 2>&1
taskkill /F /IM promtail-windows-amd64.exe >nul 2>&1

rem --- 5. 路径变更检测 ---
if not "%LAST_PATH%"=="%BASE_DIR%" (
    if not "%LAST_PATH%"=="" (
        echo [日志系统] 检测到运行目录变更

        echo [日志系统] 正在重置 Promtail 读取进度...
        if exist "%BASE_DIR%\config\promtail-positions.yaml" del "%BASE_DIR%\config\promtail-positions.yaml"
    )
    set "LAST_PATH=%BASE_DIR%"
)

rem --- 6. 自动下载组件 ---
set "LOKI_VER=3.6.4"
set "PROMTAIL_VER=3.6.4"
set "LOKI_URL=https://github.com/grafana/loki/releases/download/v%LOKI_VER%/loki-windows-amd64.exe.zip"
set "PROMTAIL_URL=https://github.com/grafana/loki/releases/download/v%PROMTAIL_VER%/promtail-windows-amd64.exe.zip"

if not exist "bin\loki-windows-amd64.exe" (
    echo [下载器] 未找到 Loki，准备下载...
    if not exist "download\loki.zip" curl -L -o "download\loki.zip" "%LOKI_URL%"
    if exist "download\loki.zip" tar -xf "download\loki.zip" -C "bin"
)

if not exist "bin\promtail-windows-amd64.exe" (
    echo [下载器] 未找到 Promtail，准备下载...
    if not exist "download\promtail.zip" curl -L -o "download\promtail.zip" "%PROMTAIL_URL%"
    if exist "download\promtail.zip" tar -xf "download\promtail.zip" -C "bin"
)

rem --- 7. 配置文件检查 ---
if not exist "config\loki-config.yaml" (
    echo [错误] 缺少配置文件: config\loki-config.yaml

    echo [提示] 5秒后自动退出...
    timeout /t 5 >nul
    exit /b 1
)
if not exist "config\promtail-config.yaml" (
    echo [错误] 缺少配置文件: config\promtail-config.yaml

    echo [提示] 5秒后自动退出...
    timeout /t 5 >nul
    exit /b 1
)

rem --- 8. 启动服务与配置写入 ---
echo [日志系统] 正在启动服务...

rem 初始化配置文件 (ShellPID 设为 0，因为窗口马上就关闭了)
echo [Runtime]> "%RUNTIME_CONFIG%"
echo ShellPID=0>> "%RUNTIME_CONFIG%"
echo LastPath=%LAST_PATH%>> "%RUNTIME_CONFIG%"

rem 启动 Loki 并追加 PID
echo [1/2] 启动 Loki...

powershell -Command "$p = Start-Process -FilePath 'bin\loki-windows-amd64.exe' -ArgumentList '-config.file=config\loki-config.yaml' -WindowStyle Hidden -RedirectStandardOutput 'log\loki.out.log' -RedirectStandardError 'log\loki.err.log' -PassThru; \"LokiPID=$($p.Id)\" | Out-File '%RUNTIME_CONFIG%' -Append -Encoding ascii"

rem 启动 Promtail 并追加 PID
echo [2/2] 启动 Promtail...

powershell -Command "$p = Start-Process -FilePath 'bin\promtail-windows-amd64.exe' -ArgumentList '-config.file=config\promtail-config.yaml' -WindowStyle Hidden -RedirectStandardOutput 'log\promtail.out.log' -RedirectStandardError 'log\promtail.err.log' -PassThru; \"PromtailPID=$($p.Id)\" | Out-File '%RUNTIME_CONFIG%' -Append -Encoding ascii"

echo [成功] 服务已在后台启动。


echo [提示] 3秒后自动关闭此窗口...


timeout /t 3 >nul

exit