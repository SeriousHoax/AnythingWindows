@echo off

rem Apply registry tweak to set RealTimeIsUniversal to 1
echo Applying registry tweak...

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /t REG_DWORD /d 1 /f

pause
