@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title MSSQL Arsenal Launcher

:showLogo
cls
echo.
echo   ================================================================================
echo.
echo                               MSSQL ARSENAL v2.0.0
echo                     Advanced MSSQL Vulnerability Assessment
echo.
echo   ================================================================================
echo.
echo   +------------------------------------------------------------------------------+
echo   ^|  [WARNING] This tool is for authorized testing only. Unauthorized scanning   ^|
echo   ^|            of others' systems is illegal!                                     ^|
echo   ^|  [警告] 本工具仅限合法授权测试使用，未经授权扫描他人系统属违法行为！         ^|
echo   ^|  MSSQL Arsenal v2.0.0 - Ultimate Scanning ^& Exploitation Framework           ^|
echo   +------------------------------------------------------------------------------+
echo.
echo   [1] Install/Update Dependencies (pip install -r requirements.txt)
echo   [2] Launch Graphical Interface (GUI)
echo   [3] Enter Command-Line Interactive Mode
echo   [4] Show Help
echo   [5] Exit
echo.
set /p choice="Please enter option number [1-5]: "

if "%choice%"=="1" goto install_deps
if "%choice%"=="2" goto run_gui
if "%choice%"=="3" goto run_interactive
if "%choice%"=="4" goto show_help
if "%choice%"=="5" exit /b 0
echo Invalid choice, please try again.
timeout /t 2 >nul
goto showLogo

:install_deps
cls
echo Checking and installing dependencies...
echo.
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.8+ and add to PATH.
    pause
    goto showLogo
)
echo Running: pip install -r requirements.txt
echo.
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Dependency installation failed. Check network or install manually.
) else (
    echo [SUCCESS] Dependencies installed.
)
echo.
pause
goto showLogo

:run_gui
cls
echo Launching GUI...
python mssql_arsenal.py --gui
if errorlevel 1 (
    echo [ERROR] Failed to start GUI. Check if all dependencies are installed or see mssql_arsenal.log.
    pause
)
goto showLogo

:run_interactive
cls
echo Entering interactive mode (type 'help' for commands, Ctrl+C to exit)...
echo.
python mssql_arsenal.py
goto showLogo

:show_help
cls
echo ============================== MSSQL Arsenal Help ==============================
echo.
echo Basic usage:
echo   python mssql_arsenal.py -t ^<target^>
echo.
echo Examples:
echo   python mssql_arsenal.py -t 192.168.1.0/24 --exploit rdp --report html
echo   python mssql_arsenal.py -t file://targets.txt --users users.txt --passwords pass.txt
echo   python mssql_arsenal.py --gui
echo   python mssql_arsenal.py --master
echo   python mssql_arsenal.py --worker 192.168.1.100
echo.
echo Main arguments:
echo   -t, --target           Target (CIDR / IP range / file://path / domain)
echo   -p, --port             Port(s), comma-separated (default 1433)
echo   --users                User dictionary file
echo   --passwords            Password dictionary file
echo   --concurrency          Scan concurrency (default 500)
echo   --timeout              Connection timeout in seconds (default 3.0)
echo   --rate-limit           Brute force rate limit (0 = unlimited)
echo   --strategy             Brute strategy: ip_first / cred_first
echo   --tls                  Enable TLS encryption
echo   --windows-auth         Use Windows integrated authentication
echo   --kerberos             Use Kerberos authentication (requires prior kinit)
echo   --proxy                SOCKS5 proxy (e.g. socks5://127.0.0.1:1080)
echo   --exploit              Exploit mode: rdp / fileless / clr / ole / plugin / none
echo   --lhost                Reverse IP for fileless mode
echo   --lport                Reverse port (default 4444)
echo   --no-honeypot          Disable honeypot detection
echo   --no-cve               Disable CVE detection
echo   --report               Generate report: json / html
echo   -o, --output           Report output file
echo   --hide-passwords       Hide passwords in reports
echo   --master               Start distributed master node
echo   --worker               Start distributed worker node (format: IP[:PORT])
echo   --gui                  Launch GUI
echo   --version              Show version
echo.
pause
goto showLogo