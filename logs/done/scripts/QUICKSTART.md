# Quick Reference: Cross-Compilation Scripts
Created: 2026-01-07

## What do these scripts do?

These scripts use Docker to cross-compile Rustyjack for Raspberry Pi ARM architectures on your Windows machine.

## Script Comparison

| Script | Platform | What it does | Output |
|--------|----------|--------------|--------|
| `build_arm64.sh` | Linux/macOS | Build for 64-bit ARM (aarch64) | `target-64/aarch64-unknown-linux-gnu/debug/rustyjack-ui` |
| `build_arm64.ps1` | **Windows** | Same as above | Same output |
| `build_arm32.sh` | Linux/macOS | Build for 32-bit ARM (armv7) | `target-32/armv7-unknown-linux-gnueabihf/debug/rustyjack-ui` |
| `build_arm32.ps1` | **Windows** | Same as above | Same output |

## Quick Start (Windows)

### Prerequisites
1. Install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/)
2. Enable WSL 2 (Docker Desktop will prompt you)
3. Restart Docker Desktop after installation

### Build Commands

```powershell
# For 64-bit Raspberry Pi OS (Pi Zero 2 W, Pi 3/4/5)
.\scripts\build_arm64.ps1

# For 32-bit Raspberry Pi OS (Pi Zero 2 W)
.\scripts\build_arm32.ps1
```

## Quick Start (Linux/macOS)

```bash
# For 64-bit Raspberry Pi OS
./scripts/build_arm64.sh

# For 32-bit Raspberry Pi OS
./scripts/build_arm32.sh
```

## What happens during build?

1. **Docker image is built** (first time only, ~5-10 min)
   - Downloads Rust ARM toolchain
   - Installs build dependencies
   
2. **Cargo compiles the project** (~15-30 min first time)
   - Uses QEMU to emulate ARM CPU
   - Compiles all Rust crates for target architecture
   - Subsequent builds are much faster (cached)

3. **Binary is written to target directory**
   - ARM64: `target-64/aarch64-unknown-linux-gnu/debug/rustyjack-ui`
   - ARM32: `target-32/armv7-unknown-linux-gnueabihf/debug/rustyjack-ui`

## Do the bash scripts work on Windows?

**No, not directly.** The `.sh` scripts are bash scripts that require a Unix-like environment.

**But you have options:**

1. ✅ **Use the PowerShell versions** (`.ps1`) - Works in native Windows PowerShell
2. ✅ **Run bash scripts in WSL 2** - If you have Ubuntu/Debian in WSL
3. ❌ **Run bash scripts in PowerShell** - Won't work without bash interpreter

## Can I run these on Windows with Docker?

**Yes!** Use the PowerShell versions (`.ps1`). They do exactly the same thing as the bash versions.

Requirements:
- Docker Desktop for Windows (includes QEMU for ARM emulation)
- WSL 2 enabled (Docker Desktop uses this)

## What if I don't have Docker?

You have two options:

1. **Install Docker Desktop** (recommended)
   - Free for personal use
   - Enables cross-compilation
   - Download: https://www.docker.com/products/docker-desktop/

2. **Use a Raspberry Pi for builds**
   - Clone repo on the Pi
   - Run `cargo build` directly (much faster, native compilation)
   - No cross-compilation needed

## Troubleshooting

### "Docker not found"
- Install Docker Desktop and make sure it's running
- Check if Docker is in your PATH: `docker --version`

### "Platform not supported" or "no matching manifest"
- Enable QEMU: `docker run --rm --privileged multiarch/qemu-user-static --reset -p yes`
- Restart Docker Desktop

### Build is very slow
- This is normal for QEMU emulation (10-30 minutes first build)
- Subsequent builds are faster due to caching
- Consider building on a Raspberry Pi for faster compilation

### Permission errors
- Run Docker Desktop as Administrator
- Check Docker Desktop file sharing settings

## For Developers

### Running arbitrary commands in container

```powershell
# ARM64 container
.\docker\arm64\run.ps1 cargo test --target aarch64-unknown-linux-gnu

# ARM32 container
.\docker\arm32\run.ps1 cargo test --target armv7-unknown-linux-gnueabihf

# Get a shell in the container
.\docker\arm64\run.ps1 bash
```

### Release builds

```powershell
# ARM64 release build
.\docker\arm64\run.ps1 env CARGO_TARGET_DIR=/work/target-64 cargo build --release --target aarch64-unknown-linux-gnu -p rustyjack-ui

# ARM32 release build
.\docker\arm32\run.ps1 env CARGO_TARGET_DIR=/work/target-32 cargo build --release --target armv7-unknown-linux-gnueabihf -p rustyjack-ui
```

Release binaries are optimized and smaller but take longer to compile.

## Architecture Summary

```
Windows PowerShell
    ↓
docker/arm64/run.ps1 or docker/arm32/run.ps1
    ↓
Docker Desktop (with QEMU/binfmt)
    ↓
ARM Linux Container (Rust toolchain)
    ↓
cargo build (cross-compilation)
    ↓
ARM binary → target-XX/[arch]/debug/rustyjack-ui
```

## See Also

- Full documentation: `BUILD_WINDOWS.md`
- Docker configurations: `docker/arm64/Dockerfile`, `docker/arm32/Dockerfile`
- Bash script equivalents: `build_arm64.sh`, `build_arm32.sh`
