@echo off

rem Remove RealTimeIsUniversal from the registry
echo Removing RealTimeIsUniversal from the registry...

reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /f

pause
