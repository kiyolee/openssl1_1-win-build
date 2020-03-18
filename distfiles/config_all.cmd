setlocal

set OPENSSL_VER=1.1.1e
set OPENSSL_VER_SED=1\.1\.1e
set OPENSSL_BASE=openssl-%OPENSSL_VER%
set OPENSSL_BASE_SED=openssl-%OPENSSL_VER_SED%
set OPENSSL_DIR=..\%OPENSSL_BASE%
set OPENSSL_DIR_SED=\.\.\\\\openssl-%OPENSSL_VER_SED%

set ZLIB_DIR=..\zlib

mkdir dll64
mkdir lib64
mkdir dll32
mkdir lib32

pushd dll64
perl %OPENSSL_DIR%\Configure --prefix="%ProgramFiles%\OpenSSL-1_1" --with-zlib-include=%ZLIB_DIR% --with-zlib-lib=%ZLIB_DIR%\build\x64\Release\libz-static.lib VC-WIN64A-masm no-dynamic-engine zlib
call :genfile
call :clndir
popd

pushd lib64
perl %OPENSSL_DIR%\Configure --prefix="%ProgramFiles%\OpenSSL-1_1" --with-zlib-include=%ZLIB_DIR% --with-zlib-lib=%ZLIB_DIR%\build\x64\Release\libz-static.lib VC-WIN64A-masm no-shared no-dynamic-engine zlib
call :genfile
call :clndir
popd

pushd dll32
perl %OPENSSL_DIR%\Configure --prefix="%ProgramFiles(x86)%\OpenSSL-1_1" --with-zlib-include=%ZLIB_DIR% --with-zlib-lib=%ZLIB_DIR%\build\Release\libz-static.lib VC-WIN32 no-dynamic-engine zlib
call :genfile
call :clndir
popd

pushd lib32
perl %OPENSSL_DIR%\Configure --prefix="%ProgramFiles(x86)%\OpenSSL-1_1" --with-zlib-include=%ZLIB_DIR% --with-zlib-lib=%ZLIB_DIR%\build\Release\libz-static.lib VC-WIN32 no-shared no-dynamic-engine zlib
call :genfile
call :clndir
popd

goto :end

:genfile
perl -I. -Mconfigdata %OPENSSL_DIR%\util\dofile.pl -omakefile %OPENSSL_DIR%\crypto\include\internal\bn_conf.h.in > bn_conf.h
perl -I. -Mconfigdata %OPENSSL_DIR%\util\dofile.pl -omakefile %OPENSSL_DIR%\crypto\include\internal\dso_conf.h.in > dso_conf.h
perl -I. -Mconfigdata %OPENSSL_DIR%\util\dofile.pl -omakefile %OPENSSL_DIR%\include\openssl\opensslconf.h.in > opensslconf.h
perl -I. -Mconfigdata %OPENSSL_DIR%\util\dofile.pl -omakefile %OPENSSL_DIR%\apps\CA.pl.in > apps\CA.pl
perl -I. -Mconfigdata %OPENSSL_DIR%\util\dofile.pl -omakefile %OPENSSL_DIR%\apps\tsget.in > apps\tsget.pl
perl -I. -Mconfigdata %OPENSSL_DIR%\util\dofile.pl -omakefile %OPENSSL_DIR%\tools\c_rehash.in > tools\c_rehash.pl
ren configdata.pm configdata.pm.org
sed -e "s/%OPENSSL_DIR_SED%/\./g" configdata.pm.org > configdata.pm
dos2unix bn_conf.h dso_conf.h opensslconf.h apps\CA.pl apps\tsget.pl tools\c_rehash.pl
exit /b

:clndir
@echo off
call :clndir0
@echo on
exit /b

:clndir0
for /d %%d in ( * ) do (
    pushd %%d
    call :clndir0
    popd
    rmdir %%d 2>nul
)
exit /b

:end
endlocal
