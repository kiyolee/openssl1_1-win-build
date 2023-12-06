@echo off
setlocal

cd %~dp0\..
set MY_ROOT=%cd%

echo ROOT: %MY_ROOT%
echo.

if .%1. == .. goto :all
set TEST_BUILDS=%*
goto :start
:all
set TEST_BUILDS=build-VS*
goto :start

:start
for /d %%d in ( %TEST_BUILDS% ) do (
    if exist %%d\ (
        for %%r in ( Release Debug x64\Release x64\Debug ) do (
            if exist %MY_ROOT%\%%d\%%r\openssl.exe (
                call test\test_one.cmd %%d\%%r
                echo.
            )
            if exist %MY_ROOT%\%%d\%%r\openssl-static.exe (
                call test\test_one.cmd %%d\%%r -static
                echo.
            )
        )
    )
)

endlocal
