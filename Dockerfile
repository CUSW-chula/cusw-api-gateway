# Dockerfile
# Build stage
FROM rust:1.85-alpine3.20 as builder

# Install musl build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    postgresql-dev \
    build-base

WORKDIR /app

# Create dummy project to cache dependencies
RUN cargo init --bin
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release

# Copy real source code
COPY src ./src
COPY config ./config

# Build final binary
RUN cargo build --release

# Runtime stage
FROM alpine:3.20

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libgcc

WORKDIR /app

# Copy built binary and configs
COPY --from=builder \
    /app/target/release/api-gateway \
    /app/config/users.toml \
    /app/config/projects.toml \
    ./

# Run as non-root user
RUN adduser -D api-gateway 
USER api-gateway 

EXPOSE 5000

ENTRYPOINT ["./api-gateway"]