FROM rust:1.81

RUN apt-get install pkgconf libssl-dev

WORKDIR /usr/src/masquerade
COPY . .

RUN cargo install --path server

EXPOSE 3478/udp

CMD ["masquerade"]
