@echo off
chcp 65001 >nul
title Network Traffic Watchdog — Instalace

echo.
echo  ╔══════════════════════════════════════════╗
echo  ║   Network Traffic Watchdog — Instalace   ║
echo  ╚══════════════════════════════════════════╝
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [CHYBA] Python není nalezen. Nainstalujte Python 3.10+ z https://python.org
    pause
    exit /b 1
)

echo [1/3] Aktualizuji pip...
python -m pip install --upgrade pip --quiet

echo [2/3] Instaluji závislosti...
python -m pip install -r requirements.txt

if errorlevel 1 (
    echo.
    echo [CHYBA] Instalace závislostí selhala.
    pause
    exit /b 1
)

echo [3/3] Vytvářím složky...
if not exist "data" mkdir data
if not exist "logs" mkdir logs

echo.
echo  ✓ Instalace dokončena!
echo.
echo  Spuštění aplikace:
echo    start.bat          — spustí na pozadí (doporučeno)
echo    python main.py     — spustí v tomto okně
echo.

set /p ans="Přidat do spouštění při startu Windows? [a/N] "
if /i "%ans%"=="a" goto autostart
goto done

:autostart
echo.
echo Přidávám do Task Scheduleru (vyžaduje oprávnění správce)...
schtasks /create /tn "NetworkWatchdog" /tr "\"%CD%\start_hidden.bat\"" /sc ONLOGON /rl HIGHEST /f >nul 2>&1
if errorlevel 1 (
    echo [VAROVÁNÍ] Nepodařilo se přidat do Task Scheduleru.
    echo            Spusťte setup.bat jako správce pro autostart.
) else (
    echo  ✓ Přidáno do Task Scheduleru — spustí se při přihlášení.
)

:done
echo.
pause
