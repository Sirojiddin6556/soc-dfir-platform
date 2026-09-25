# ==========================================
# STAGE 1: Builder
# ==========================================
FROM rust:1.80-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release --bin engine-server

# ==========================================
# STAGE 2: Production Distroless/Slim Runtime
# ==========================================
FROM debian:bookworm-slim AS runtime

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    tshark \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# Run as unprivileged nonroot user
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/bash -m appuser

# Prepare directories for CAS storage and SQLite DB
RUN mkdir -p /app/data /app/cas /app/logs && \
    chown -R appuser:appgroup /app

COPY --from=builder /app/target/release/engine-server /app/engine-server
RUN chown appuser:appgroup /app/engine-server && chmod +x /app/engine-server

USER appuser:appgroup

ENV RUST_LOG=info
ENV APP_PORT=8080
ENV CAS_STORAGE_PATH=/app/cas
ENV DB_PATH=/app/data/ctf_workspace.db

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:8080/health/live || exit 1

ENTRYPOINT ["/app/engine-server"]
