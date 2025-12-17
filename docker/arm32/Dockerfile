FROM --platform=linux/arm/v7 rust:1.84-bullseye

# Install system deps needed for builds
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        libudev-dev \
        clang \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Add ARMv7 target for cargo
RUN rustup target add armv7-unknown-linux-gnueabihf

WORKDIR /work
CMD ["/bin/bash"]
