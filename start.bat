@echo off
:: Spustí watchdog pomocí pythonw (žádné konzolové okno)
:: Ikona se zobrazí v systémovém trayi.
cd /d "%~dp0"
start "" pythonw main.py
