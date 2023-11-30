# syntax=docker/dockerfile:1

######### Build Stage

ARG RUST_VERSION=1.74.0
ARG APP_NAME=new-api-rs
FROM rust:${RUST_VERSION}-slim-bullseye AS build
ARG APP_NAME
WORKDIR /app

RUN apt update
RUN apt install -y pkg-config libssl-dev

RUN --mount=type=bind,source=api,target=api \
    --mount=type=bind,source=traits,target=traits \
    --mount=type=bind,source=oauth,target=oauth \
    --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
    --mount=type=cache,target=/app/target/ \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    <<EOF
set -e
cargo build --locked --release
cp ./target/release/$APP_NAME /bin/server
EOF

######### Run Stage

FROM debian:bullseye-slim AS final

WORKDIR /home

COPY --from=build /bin/server /bin/

EXPOSE 8080


CMD ["/bin/server"]
