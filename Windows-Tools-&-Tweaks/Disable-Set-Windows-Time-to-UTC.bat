@echo off
rem Remove RealTimeIsUniversal from the registry
echo Removing RealTimeIsUniversal from the registry...
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /f

rem Set w32time service to Automatic (Delayed start)
echo Enabling the w32time service...
sc config w32time start= delayed-auto

echo Done.
pause