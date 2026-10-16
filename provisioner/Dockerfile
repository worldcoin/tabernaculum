# syntax=docker/dockerfile:1
# Base image for deploy repos, which add their EIF at /home/enclave.eif.
FROM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS build
USER root
WORKDIR /app
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY bundle/ bundle/
COPY sandbox/ sandbox/
COPY provisioner/ provisioner/
RUN rustup show && rustup target add x86_64-unknown-linux-musl \
    && cargo build --locked --release --target x86_64-unknown-linux-musl \
        -p tabernaculum-provisioner

FROM public.ecr.aws/amazonlinux/amazonlinux:2023
RUN dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel \
    awscli-2 tar gzip binutils && dnf clean all
COPY --from=build /app/target/x86_64-unknown-linux-musl/release/tabernaculum-provisioner \
    /usr/local/bin/tabernaculum-provisioner
ENTRYPOINT ["/usr/local/bin/tabernaculum-provisioner"]
