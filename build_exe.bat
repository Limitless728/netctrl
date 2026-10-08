@echo off
echo ============================================================
echo  NetCtrl - Build Standalone EXE
echo ============================================================

echo [0/3] Checking for MSVC linker...

REM Try to find link.exe in current PATH
where link.exe >nul 2>&1
if not errorlevel 1 goto :msvc_ok

REM Not found — try to locate and run vcvars64.bat
set VCVARS=
set "VS_ENT=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
set "VS_COM=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
set "VS_PRO=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
set "VS_BT=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set "VS_19C=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
set "VS_19E=C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

for %%P in ("%VS_ENT%" "%VS_COM%" "%VS_PRO%" "%VS_BT%" "%VS_19C%" "%VS_19E%") do (
    if exist %%P set "VCVARS=%%~P"
    if not "%VCVARS%"=="" goto :found_vcvars
)

echo.
echo [ERROR] MSVC linker ^(link.exe^) not found.
echo.
echo Rust on Windows requires Visual Studio Build Tools with C++ support.
echo.
echo Download here: https://visualstudio.microsoft.com/visual-cpp-build-tools/
echo During install, select: "Desktop development with C++"
echo.
echo After installing, re-run this script.
pause
exit /b 1

:found_vcvars
echo   Found vcvars64.bat at: %VCVARS%
echo   Initializing MSVC environment...
call "%VCVARS%" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Failed to initialize MSVC environment.
    pause
    exit /b 1
)

where link.exe >nul 2>&1
if errorlevel 1 (
    echo [ERROR] link.exe still not available after running vcvars64.bat.
    pause
    exit /b 1
)

:msvc_ok
echo   MSVC linker found: OK

echo [1/3] Building Rust engine...
cd rust_engine
cargo build --release
if errorlevel 1 (
    echo [ERROR] Rust build failed. Make sure Rust is installed: https://rustup.rs
    pause
    exit /b 1
)
copy /Y target\release\rust_engine.exe ..\rust_engine.exe
cd ..

echo [2/3] Installing PyInstaller...
pip install pyinstaller

echo [3/3] Building Python EXE...
set "ICON_ARG="
if exist icon.ico set "ICON_ARG=--icon icon.ico"

pyinstaller --onefile --noconsole --uac-admin ^
    --add-data "rust_engine.exe;." ^
    --add-data "device_names.json;." ^
    --add-data "web;web" ^
    %ICON_ARG% ^
    --workpath build_pkg ^
    --distpath dist_release ^
    --exclude-module matplotlib ^
    --exclude-module pygame ^
    --exclude-module PIL ^
    --exclude-module IPython ^
    --clean ^
    --name "NetCtrl" ^
    main.py

echo ============================================================
echo  Done! Find NetCtrl.exe in the dist_release/ folder.
echo  Run NetCtrl.exe as Administrator.
echo ============================================================
pause