FROM rust

RUN apt update && apt install -y openssh-server \
    clang make pkg-config nettle-dev libssl-dev capnproto

RUN cargo install --git https://gitlab.com/wiktor/pks-soft.git --rev bb57d56

COPY Cargo.toml Cargo.lock /app/
WORKDIR /app
RUN mkdir .cargo
RUN mkdir src
RUN touch src/main.rs
RUN cargo vendor > .cargo/config

RUN rm src/main.rs
COPY src /app/src
RUN cargo build

COPY tests /app/tests
WORKDIR /app/tests
RUN ./test.sh
