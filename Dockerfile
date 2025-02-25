# Build stage
FROM rust:1.85-slim-bookworm as builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-dev libssl-dev libpq-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# First copy Cargo files
COPY Cargo.toml Cargo.lock ./

# Create dummy source file for dependency caching
RUN mkdir src && echo 'fn main() {}' > src/main.rs

# Build dependencies
RUN cargo build --release

# Now copy real source code
COPY src ./src
COPY config ./config

# Touch main.rs to ensure rebuild
RUN touch src/main.rs

# Build final binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/api-gateway .
COPY --from=builder /app/config/*.toml ./config/

RUN useradd -m api-gateway
USER api-gateway

EXPOSE 8000
ENTRYPOINT ["./api-gateway"]
