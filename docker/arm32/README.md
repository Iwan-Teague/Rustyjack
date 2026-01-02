ARM32 build container (Pi Zero 2 W class on 32-bit Pi OS). This sets up Rust with the armv7 target and the minimal native deps needed for the Rustyjack binaries.

Prereqs
- Docker Desktop with binfmt/qemu enabled (run once if needed: `docker run --rm --privileged tonistiigi/binfmt --install all`).

Build and enter the container
```bash
./docker/arm32/run.sh
```
This builds the image (if needed), mounts the repo at `/work`, and drops you into a shell on an ARMv7 userland with `TMPDIR=/work/tmp` so temp files stay in the repo.

Inside the container, build the three Rustyjack binaries for 32-bit Pi:
```bash
cargo build --target armv7-unknown-linux-gnueabihf -p rustyjack-ui -p rustyjack-core -p rustyjack-daemon
```

Notes
- The Dockerfile uses `rust:1.84-bullseye` on `--platform linux/arm/v7`. Use the arm64 image for 64-bit Pi OS builds.
