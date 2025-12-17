ARMv7 build container (Pi Zero 2 W class). This sets up Rust with the armv7 target and the minimal native deps needed for `rustyjack-ui`.

Prereqs
- Docker Desktop with binfmt/qemu enabled (run once if needed: `docker run --rm --privileged tonistiigi/binfmt --install all`).

Build and enter the container
```bash
./docker/armv7/run.sh
```
This builds the image (if needed), mounts the repo at `/work`, and drops you into a shell on an ARMv7 userland with `TMPDIR=/work/tmp` so temp files stay in the repo.

Inside the container, build for Pi:
```bash
cargo build --target armv7-unknown-linux-gnueabihf -p rustyjack-ui
```

Notes
- The Dockerfile uses `rust:1.78-bullseye` on `--platform linux/arm/v7`. Switch to `arm64` and the `aarch64-unknown-linux-gnu` target if you want 64-bit builds.
