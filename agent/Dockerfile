FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev protoc && rustup default nightly && rustup component add rustfmt
WORKDIR /usr/src/strapper-agent
COPY . .
RUN cargo install --path agent/

FROM alpine
COPY --from=builder /usr/local/cargo/bin/agent /usr/local/bin/agent
CMD ["agent"]
