@echo off
REM Apply registry settings to set RealTimeIsUniversal to 1
echo Applying registry settings...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /t REG_DWORD /d 1 /f

REM Disable the w32time service
echo Disabling w32time service...
sc config w32time start= disabled

echo Done.
pause