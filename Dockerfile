FROM rust:1-bullseye

RUN cargo install cargo-deb

RUN apt-get -qy update
RUN apt-get -qy install lsb-release

WORKDIR /root
RUN mkdir /root/OUTPUT
COPY . .

