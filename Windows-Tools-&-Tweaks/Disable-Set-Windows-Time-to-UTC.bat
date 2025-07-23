@echo off
REM Remove RealTimeIsUniversal from the registry
echo Removing RealTimeIsUniversal from the registry...
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /f

REM Set w32time service to demand start
echo Setting w32time service to demand start...
sc config w32time start= demand

echo Done.
pause