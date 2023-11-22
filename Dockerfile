ARG DEBIAN_VER=bookworm
FROM rust:1-${DEBIAN_VER}

RUN apt-get -qy update
RUN apt-get -qy install lsb-release libssl-dev
RUN cargo install cargo-deb

WORKDIR /root
RUN mkdir /root/OUTPUT
COPY . .
