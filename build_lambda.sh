#!/bin/sh

rm -f lambda_function.zip

#buildah bud --layers=true -t musl_builder .
podman run -it --rm \
  -v ~/.cargo/registry:/usr/local/cargo/registry:z \
  -v .:/build:z \
  musl_builder \
  cargo build --release --target=x86_64-unknown-linux-musl --example=sign-in-with-google --features=session-store \
&& \
7za a  lambda_function.zip \
       target/x86_64-unknown-linux-musl/release/examples/sign-in-with-google && \
7za rn lambda_function.zip \
       target/x86_64-unknown-linux-musl/release/examples/sign-in-with-google \
       bootstrap && \
ls -l lambda_function.zip
