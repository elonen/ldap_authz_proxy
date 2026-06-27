FROM rust:1-trixie

ARG RUST_TARGET=x86_64-unknown-linux-musl

RUN apt-get -qy update
RUN apt-get -qy install musl-tools
RUN rustup target add ${RUST_TARGET}
RUN cargo install cargo-deb

WORKDIR /root
RUN mkdir /root/OUTPUT
COPY . .
