FROM --platform=linux/arm64 scratch

EXPOSE 3478/udp

COPY ./target/x86_64-unknown-linux-musl/release/masquerade /masquerade

CMD ["/masquerade"]
