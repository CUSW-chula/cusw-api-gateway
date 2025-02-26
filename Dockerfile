# Build stage
FROM rust:1.85-alpine as builder

RUN apk add --no-cache \
    musl-dev openssl-dev postgresql-dev build-base pkgconfig

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
FROM alpine:latest

RUN apk add --no-cache \
    ca-certificates libgcc libssl3

WORKDIR /app

COPY --from=builder /app/target/release/api-gateway .
COPY --from=builder /app/config/*.toml ./config/

RUN adduser -D api-gateway
USER api-gateway

EXPOSE 8000
ENTRYPOINT ["./api-gateway"]
