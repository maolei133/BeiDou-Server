@echo off
@title 北斗服务端 - 全自动一体化启动脚本
chcp 65001

:start
rem --- 1. 文件自动更新 ---
set "newJar=BeiDou_new.jar"
set "oldJar=BeiDou.jar"

if exist "%newJar%" (
    if exist "%oldJar%" (
        echo [更新器] 正在删除旧版服务端...
        del "%oldJar%"
    )
    echo [更新器] 检测到新版本，正在应用更新...
    ren "%newJar%" "%oldJar%"
    echo [更新器] 更新完成。
)

rem --- 2. 日志系统全自动部署与启动 ---
echo [日志] 正在检查并启动日志系统...

rem 检查是否为 Windows 环境
if "%OS%"=="Windows_NT" (
    rem 检查并启动日志系统 (假设 LogSystem 在上级目录)
    if exist "..\LogSystem\Windows\start-logging.bat" (
        echo [日志] 发现日志系统，正在启动...

        rem 使用 call 同步调用启动脚本，确保日志系统准备就绪后再启动服务端
        rem 注意：start-logging.bat 已经改为"启动即焚"模式，启动完成后会自动退出，所以这里使用 call 是安全的
        call "..\LogSystem\Windows\start-logging.bat"

        echo [日志] 日志系统启动流程已完成。
    ) else (
        echo [警告] 未找到日志启动脚本 ..\LogSystem\Windows\start-logging.bat
    )
) else (
    rem Linux/Docker 环境
    if exist docker-compose.yml (
        echo [日志] 检测到 Docker 环境，将通过 Docker Compose 启动服务...
        docker-compose up -d
    ) else (
        echo [警告] 未找到 docker-compose.yml，无法启动日志系统。
    )
)

rem --- 3. 启动游戏服务器 ---
echo.
echo [服务端] 正在启动游戏服务器...
jdk-21.0.2\bin\java.exe -Dspring.config.location=application.yml -jar "%oldJar%"

rem --- 4. 自动重启 (用于热更新) ---
if exist "%newJar%" (
	echo [更新器] 检测到新的更新，将在 15 秒后重启服务器...
	ping 127.0.0.1 -n 15 >nul
	goto start
)

pause