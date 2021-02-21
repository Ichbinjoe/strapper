FROM fedora:latest

WORKDIR /r

RUN dnf install curl gcc systemd-devel openssl-devel -y
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rustup.sh
RUN sh rustup.sh -y
RUN /root/.cargo/bin/rustup default nightly
