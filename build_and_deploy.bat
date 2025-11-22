@echo off
REM Rustyjack Cross-Compilation and Deployment Script for Windows
REM This script will install Rust, cross-compile for Pi Zero W 2, and deploy

echo ============================================
echo Rustyjack Build and Deploy Script
echo ============================================
echo.

REM Check if Rust is already installed
where rustc >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [OK] Rust is already installed
    rustc --version
) else (
    echo [STEP 1/6] Installing Rust...
    echo Downloading Rust installer...
    powershell -Command "Invoke-WebRequest -Uri https://win.rustup.rs/x86_64 -OutFile %TEMP%\rustup-init.exe"
    
    echo Installing Rust (this may take a few minutes)...
    %TEMP%\rustup-init.exe -y --default-toolchain stable
    
    echo Refreshing environment...
    call "%USERPROFILE%\.cargo\env.bat"
    
    echo [OK] Rust installed successfully
)

echo.
echo [STEP 2/6] Adding ARM target for Raspberry Pi...
rustup target add armv7-unknown-linux-gnueabihf
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to add ARM target
    pause
    exit /b 1
)

echo.
echo [STEP 3/6] Installing cargo-zigbuild (cross-compilation tool)...
cargo install cargo-zigbuild
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to install cargo-zigbuild
    echo Trying alternative method...
    goto :use_docker
)

echo.
echo [STEP 4/6] Building rustyjack-core for ARM...
cd /d "%~dp0rustyjack-core"
cargo zigbuild --release --target armv7-unknown-linux-gnueabihf
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to build rustyjack-core
    echo.
    echo Trying Docker method instead...
    goto :use_docker
)
echo [OK] rustyjack-core built successfully

echo.
echo [STEP 5/6] Building rustyjack-ui for ARM...
cd /d "%~dp0rustyjack-ui"
cargo zigbuild --release --target armv7-unknown-linux-gnueabihf
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to build rustyjack-ui
    goto :use_docker
)
echo [OK] rustyjack-ui built successfully
goto :deploy

:use_docker
echo.
echo ============================================
echo Using Docker method (requires Docker Desktop)
echo ============================================
echo.
where docker >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Docker is not installed or not in PATH
    echo.
    echo Please install Docker Desktop from: https://www.docker.com/products/docker-desktop
    echo.
    echo After installing Docker, run this script again.
    pause
    exit /b 1
)

echo [STEP 4/6] Building rustyjack-core with Docker...
cd /d "%~dp0"
docker run --rm -v "%CD%":/project -w /project/rustyjack-core messense/rust-musl-cross:armv7-musleabihf cargo build --release
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to build rustyjack-core with Docker
    pause
    exit /b 1
)
echo [OK] rustyjack-core built successfully

echo.
echo [STEP 5/6] Building rustyjack-ui with Docker...
docker run --rm -v "%CD%":/project -w /project/rustyjack-ui messense/rust-musl-cross:armv7-musleabihf cargo build --release
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to build rustyjack-ui with Docker
    pause
    exit /b 1
)
echo [OK] rustyjack-ui built successfully

:deploy

echo.
echo [STEP 6/6] Deploying to Raspberry Pi...
echo.

REM Check which build method was used
if exist "%~dp0rustyjack-core\target\armv7-unknown-linux-gnueabihf\release\rustyjack-core" (
    set CORE_BINARY=%~dp0rustyjack-core\target\armv7-unknown-linux-gnueabihf\release\rustyjack-core
    set UI_BINARY=%~dp0rustyjack-ui\target\armv7-unknown-linux-gnueabihf\release\rustyjack-ui
) else (
    set CORE_BINARY=%~dp0rustyjack-core\target\release\rustyjack-core
    set UI_BINARY=%~dp0rustyjack-ui\target\release\rustyjack-ui
)

echo Binaries are located at:
echo   %CORE_BINARY%
echo   %UI_BINARY%
echo.

set /p PI_IP="Enter your Raspberry Pi IP address (default: 192.168.0.48): "
if "%PI_IP%"=="" set PI_IP=192.168.0.48

echo.
echo Copying rustyjack-core to Pi...
scp "%CORE_BINARY%" root@%PI_IP%:/usr/local/bin/rustyjack-core
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to copy rustyjack-core
    echo.
    echo Make sure:
    echo   1. SSH is enabled on your Pi
    echo   2. You can connect via: ssh root@%PI_IP%
    echo   3. scp is installed (comes with Git for Windows)
    pause
    exit /b 1
)

echo Copying rustyjack-ui to Pi...
scp "%UI_BINARY%" root@%PI_IP%:/usr/local/bin/rustyjack-ui
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to copy rustyjack-ui
    pause
    exit /b 1
)

echo.
echo [SUCCESS] Build and deployment complete!
echo.
echo Now SSH into your Pi and run:
echo   ssh root@%PI_IP%
echo   chmod +x /usr/local/bin/rustyjack-core
echo   chmod +x /usr/local/bin/rustyjack-ui
echo   cd /root/Rustyjack
echo   systemctl daemon-reload
echo   systemctl enable rustyjack.service
echo   systemctl start rustyjack.service
echo   systemctl status rustyjack
echo.
pause
