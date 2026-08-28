# This file is copied from: https://github.com/k4yt3x/simple-http-server/blob/master/Dockerfile
# LICENS: BSD 2-Clause "Simplified" License
#    please see https://github.com/k4yt3x/simple-http-server/blob/master/LICENSE for more details

FROM rust:1.88-alpine AS builder
WORKDIR /build
COPY . .
RUN <<EOF
    apk add --no-cache --virtual .build-deps git make musl-dev openssl-dev perl pkgconfig gcc
    RUSTFLAGS='-C link-arg=-s' cargo build \
        --features only-openssl \
        --no-default-features \
        --release
EOF

FROM gcr.io/distroless/static:nonroot
LABEL maintainer="thewawar <thewawar@gmail.com>" \
    org.opencontainers.image.source="https://github.com/TheWaWaR/simple-http-server" \
    org.opencontainers.image.description="A minimal distroless container image for TheWaWaR/simple-http-server"
COPY --from=builder \
    /build/target/release/simple-http-server \
    /usr/local/bin/simple-http-server
USER nonroot:nonroot
WORKDIR /var/www/html
EXPOSE 8000
ENTRYPOINT ["simple-http-server"]
