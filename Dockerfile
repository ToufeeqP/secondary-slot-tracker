# Two-stage build for secondary-slot-tracker (Avail BABE secondary-slot monitor).
# src/metadata.rs is a committed subxt codegen file, so no node/artifacts are
# needed at build time. Cargo.lock is committed → build with --locked.

# ---- build ----
FROM rust:1.82-bookworm AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
      pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release --locked \
    && strip target/release/secondary-slot-tracker

# ---- runtime ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/secondary-slot-tracker /usr/local/bin/secondary-slot-tracker
# Optional: bake a validator stash->name map for nicer alerts.
# COPY offchain_identities.json /app/offchain_identities.json

# Config comes from the environment, set per-app in porto.toml so testnet/mainnet
# differ only by config (no rebuild to change an endpoint):
#   WS_URL             RPC endpoint       — read by the binary via structopt env
#   SLACK_WEBHOOK_URL  Slack webhook URL  — read by post_to_slack (injected from SSM)
# RUST_LOG below is just a fallback default.
ENV RUST_LOG=info
# No EXPOSE: pure worker (outbound WS + outbound Slack webhook), no inbound port.

# Slack alerting is enabled for both testnet and mainnet; the per-env webhook URL
# comes from SLACK_WEBHOOK_URL (SSM). If that env is unset the binary logs a warn
# and skips posting, so an un-provisioned deploy is effectively log-only.
ENTRYPOINT ["secondary-slot-tracker"]
CMD ["--enable-slack"]
