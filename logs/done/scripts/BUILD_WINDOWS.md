# Windows Build Scripts for ARM Cross-Compilation
Created: 2026-01-07

This directory contains PowerShell scripts for building Rustyjack on Windows for ARM targets (Raspberry Pi).

## Prerequisites

### 1. Install Docker Desktop for Windows

Download and install [Docker Desktop](https://www.docker.com/products/docker-desktop/) for Windows.

### 2. Enable WSL 2 Backend

Docker Desktop on Windows uses WSL 2 as the backend. Make sure WSL 2 is installed:

```powershell
wsl --install
```

### 3. Enable QEMU/binfmt Support

Docker Desktop includes QEMU emulation by default. To verify it's working:

```powershell
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
```

### 4. Verify ARM Platform Support

Test that Docker can run ARM containers:

```powershell
# Test ARM64
docker run --rm --platform linux/arm64 alpine uname -m
# Should output: aarch64

# Test ARM32
docker run --rm --platform linux/arm/v7 alpine uname -m
# Should output: armv7l
```

## Usage

### Build for ARM64 (64-bit Raspberry Pi OS)

For Raspberry Pi Zero 2 W running 64-bit OS, or Raspberry Pi 3/4/5:

```powershell
.\scripts\build_arm64.ps1
```

Output binary: `target-64\aarch64-unknown-linux-gnu\debug\rustyjack-ui`

### Build for ARM32 (32-bit Raspberry Pi OS)

For Raspberry Pi Zero 2 W running 32-bit OS:

```powershell
.\scripts\build_arm32.ps1
```

Output binary: `target-32\armv7-unknown-linux-gnueabihf\debug\rustyjack-ui`

### Build Release Versions

To build optimized release binaries, modify the scripts or run directly:

```powershell
# ARM64 release
.\docker\arm64\run.ps1 env CARGO_TARGET_DIR=/work/target-64 cargo build --release --target aarch64-unknown-linux-gnu -p rustyjack-ui

# ARM32 release
.\docker\arm32\run.ps1 env CARGO_TARGET_DIR=/work/target-32 cargo build --release --target armv7-unknown-linux-gnueabihf -p rustyjack-ui
```

Release binaries will be in the `release` subdirectory instead of `debug`.

## How It Works

### Architecture

1. **PowerShell Scripts** (`build_arm*.ps1`):
   - Navigate to repository root
   - Call the Docker wrapper scripts with cargo build commands
   - Provide user feedback

2. **Docker Wrapper Scripts** (`docker/*/run.ps1`):
   - Build a Docker image with Rust toolchain for the target architecture
   - Run the container with the repository mounted as `/work`
   - Execute the provided command (e.g., cargo build) inside the container

3. **Docker Images**:
   - Based on official Rust Docker images for ARM platforms
   - Include necessary build dependencies (pkg-config, libssl, libudev, clang)
   - Use QEMU emulation to run ARM binaries on x86_64 Windows

### Volume Mapping

The scripts mount your repository root as `/work` inside the container, so:
- Source code changes are immediately visible
- Build artifacts are written back to your Windows filesystem
- The build cache is preserved between runs

## Troubleshooting

### Error: "The system cannot find the file specified" or "cannot connect to docker"

**Problem**: Docker Desktop is not running.

**Solution**:
1. Start Docker Desktop from the Windows Start menu
2. Wait for Docker to fully start (icon in system tray turns green)
3. Verify Docker is running: `docker ps`
4. Run the build script again

The PowerShell scripts now check if Docker is running and provide helpful error messages.

### Error: "docker: command not found"

Make sure Docker Desktop is installed and running. Add Docker to your PATH if needed.

### Error: "no matching manifest for windows/amd64"

This means QEMU emulation isn't working. Run:

```powershell
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
```

Then restart Docker Desktop.

### Slow Build Times

Cross-compilation with QEMU emulation is significantly slower than native builds. First builds can take 30+ minutes. Subsequent builds are faster due to caching.

### Permission Issues with Mounted Volumes

If you encounter permission errors, try running Docker Desktop with administrator privileges or check your Docker Desktop file sharing settings.

### WSL 2 Memory Issues

Large builds can consume significant memory. Adjust WSL 2 memory limits in `%USERPROFILE%\.wslconfig`:

```ini
[wsl2]
memory=8GB
processors=4
```

## Comparison: Bash vs PowerShell Scripts

| Feature | Bash Scripts (`.sh`) | PowerShell Scripts (`.ps1`) |
|---------|---------------------|----------------------------|
| Platform | Linux/macOS/WSL | Windows (native PowerShell) |
| Docker volume paths | Unix-style (`/path`) | Windows-style converted to Unix |
| Error handling | `set -euo pipefail` | `$ErrorActionPreference = "Stop"` |
| Path resolution | `$(cd ... && pwd)` | `Resolve-Path` cmdlet |
| Exit codes | `$?` / `$LASTEXITCODE` (when called from PS) | Native `$LASTEXITCODE` |

Both sets of scripts produce identical Docker images and binaries.

## Alternative: Use WSL 2 with Bash Scripts

If you prefer the original bash scripts, you can run them from WSL 2:

```bash
# From WSL Ubuntu/Debian terminal
cd /mnt/c/Users/YourName/Desktop/Rustyjack
./scripts/build_arm64.sh
```

This requires Docker Desktop's WSL 2 integration to be enabled in settings.

## Notes

- **Build cache**: The first build downloads and compiles all dependencies. Subsequent builds are much faster.
- **Separate target directories**: ARM32 and ARM64 builds use different target directories (`target-32` and `target-64`) to avoid conflicts.
- **Debug vs Release**: Debug builds are faster but produce larger, slower binaries. Use release builds for deployment.
- **Platform verification**: The container platform must match the target (e.g., `linux/arm64` for aarch64).

## See Also

- Original bash scripts: `build_arm64.sh`, `build_arm32.sh`
- Docker configuration: `docker/arm64/Dockerfile`, `docker/arm32/Dockerfile`
- Main project README: `../README.md`
