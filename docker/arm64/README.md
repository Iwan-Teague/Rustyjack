ARM64 build container (Pi Zero 2 W on 64-bit Pi OS or other ARM64 Pis). This sets up Rust with the aarch64 target and the minimal native deps needed for the Rustyjack binaries.

Prereqs
- Docker Desktop with binfmt/qemu enabled (run once if needed: `docker run --rm --privileged tonistiigi/binfmt --install all`).

Build and enter the container
```bash
./docker/arm64/run.sh
```
This builds the image (if needed), mounts the repo at `/work`, and drops you into a shell on an ARM64 userland with `TMPDIR=/work/tmp` so temp files stay in the repo.

Inside the container, build the three Rustyjack binaries for 64-bit Pi:
```bash
cargo build --target aarch64-unknown-linux-gnu -p rustyjack-ui -p rustyjack-core -p rustyjack-daemon
```

Notes
- The Dockerfile uses `rust:1.84-bullseye` on `--platform linux/arm64`. Use the armv7 image for 32-bit Pi OS builds.
