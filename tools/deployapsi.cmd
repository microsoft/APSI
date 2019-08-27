rem Copy APSI to APSILIBS

setlocal

set SCRIPT_DIR=~%dp0
cd "%SCRIPT_DIR%"
cd ..

rem Includes
robocopy APSICommon\apsi "%APSILIBS%\APSI\include\apsi" /S *.h
robocopy APSIReceiver\apsi "%APSILIBS%\APSI\include\apsi" /S *.h
robocopy APSISender\apsi "%APSILIBS%\APSI\include\apsi" /S *.h

rem Binaries
robocopy lib\x64 "%APSILIBS%\APSI\lib\x64" /S

