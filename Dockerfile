#!/usr/bin/env buildah bud -t musl_builder

FROM public.ecr.aws/docker/library/rust:1.86-alpine

RUN \
  mkdir -p /build && \
  apk add --no-cache musl-dev openssl-dev openssl-libs-static  

# Default command to build Rust cargo project
WORKDIR /build
CMD cargo build --release --target=x86_64-unknown-linux-musl

# Run container and build
#
# podman run -it --rm -v ~/.cargo/registry:/usr/local/cargo/registry:z -v .:/build:z musl_builder
#

