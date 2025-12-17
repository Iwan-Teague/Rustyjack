FROM --platform=linux/arm64 rust:1.84-bullseye

# Install system deps needed for builds
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        libudev-dev \
        clang \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Add ARM64 target for cargo
RUN rustup target add aarch64-unknown-linux-gnu

WORKDIR /work
CMD ["/bin/bash"]
