rem @echo off

setlocal
set DESTDIR=C:\Users\haoche\Documents\Libraries\APSI\x64\%1

copy %APSILIBS%\flint2\lib\x64\%1\dll_flint.dll %DESTDIR%
copy %APSILIBS%\flint2\lib\x64\%1\dll_flint.pdb %DESTDIR%
copy %APSILIBS%\mpir\lib\x64\%1\mpir.dll %DESTDIR%
copy %APSILIBS%\mpir\lib\x64\%1\mpir.pdb %DESTDIR%
copy %APSILIBS%\mpfr\lib\x64\%1\mpfr.dll %DESTDIR%
copy %APSILIBS%\mpfr\lib\x64\%1\mpfr.pdb %DESTDIR%
copy %APSILIBS%\pthreads4w-3.0.0\lib\pthreadVCE3.dll %DESTDIR%
copy %APSILIBS%\libzmq\dll\x64\%1\libzmq.dll %DESTDIR%
copy %APSILIBS%\libzmq\dll\x64\%1\libzmq.pdb %DESTDIR%
copy %APSILIBS%\libzmqpp\lib\x64\%1\zmqpp.dll %DESTDIR%
copy %APSILIBS%\libzmqpp\lib\x64\%1\zmqpp.pdb %DESTDIR%
