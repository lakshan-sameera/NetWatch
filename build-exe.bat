@echo off
:: Rebuilds dist\NetWatch.exe (portable, single file, asks for admin on launch)
cd /d "%~dp0"
python -m pip install --quiet pyinstaller psutil flask
python -m PyInstaller --noconfirm --clean --onefile --uac-admin --name NetWatch --version-file "%~dp0version_info.txt" ^
  --add-data "%~dp0static;static" --hidden-import etw_sensor --hidden-import reputation --hidden-import capture ^
  --hidden-import hashwatch --hidden-import iphistory --hidden-import netmap ^
  --distpath dist --workpath build --specpath build netwatch.py
echo.
echo Built: %~dp0dist\NetWatch.exe
pause
