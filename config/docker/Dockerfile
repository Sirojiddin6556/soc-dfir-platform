# ==========================================
# STAGE 1: Builder
# ==========================================
FROM rust:1-slim-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release --locked -p engine-server

# ==========================================
# STAGE 2: Runtime
# ==========================================
FROM debian:bookworm-slim AS runtime

WORKDIR /app

# CA certificates: vulnerability feed downloads verify TLS against the
# system trust store.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Run as unprivileged nonroot user
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /usr/sbin/nologin -m appuser && \
    mkdir -p /app/data && chown -R appuser:appgroup /app

COPY --from=builder /app/target/release/engine-server /app/engine-server
COPY apps/desktop-ui /app/ui

USER appuser:appgroup

# The engine serves the UI and the RPC API itself. Inside the container it
# listens on all interfaces; requests are still only accepted for loopback
# Host names plus the names listed in SOC_ALLOWED_HOSTS.
ENV RUST_LOG=info \
    SOC_BIND=0.0.0.0:8080 \
    SOC_DATA_DIR=/app/data \
    SOC_UI_DIR=/app/ui \
    SOC_NO_BROWSER=1

EXPOSE 8080
VOLUME ["/app/data"]

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/app/engine-server", "--healthcheck"]

ENTRYPOINT ["/app/engine-server"]
