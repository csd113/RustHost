# Build on the target architecture so published images need no emulation.
FROM rust:1.91-bookworm AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
ARG RUSTHOST_GIT_COMMIT=unknown
ENV RUSTHOST_GIT_COMMIT=${RUSTHOST_GIT_COMMIT}
RUN cargo build --locked --release --bin rusthost-cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 rusthost \
    && useradd --uid 10001 --gid rusthost --no-create-home rusthost \
    && install -d -m 0700 -o rusthost -g rusthost /data
COPY --from=builder /build/target/release/rusthost-cli /usr/local/bin/rusthost-cli
COPY --chown=10001:10001 docker/settings.toml /data/settings.toml
USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl --fail --silent http://127.0.0.1:8080/ready || exit 1
ENTRYPOINT ["rusthost-cli"]
CMD ["--data-dir", "/data", "--headless"]
