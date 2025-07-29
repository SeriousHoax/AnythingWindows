@echo off
rem Apply registry settings to set RealTimeIsUniversal to 1
echo Applying registry settings...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /t REG_DWORD /d 1 /f

rem Disable the w32time service
echo Disabling w32time service...
sc config w32time start= disabled

rem Windows's built-in time syncing method is often buggy and doesn't work. So the "Update Time" app by Sordum has been used - https://www.sordum.org/9203/update-time-v1-3/
rem copy UpdateTime folder to Program Files - Copying to the program files is not necessary but recommended to store it in the system drive
echo copying updatetime folder to program files...
xcopy "E:\Portables\UpdateTime" "C:\Program Files\UpdateTime\" /e /i /y

rem create the Update-Time service to sync time at every system startup
echo creating Update-Time service...
sc create Update-Time binpath= "\"C:\Program Files\UpdateTime\UpdateTime.exe\" /Service" displayname= "Update Time v1-3" start= auto
sc description Update-Time "Automatically Synchronize Computer date and time on Windows Startup."

echo done.
pause