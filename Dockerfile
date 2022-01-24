FROM rust

RUN apt update && apt install -y openssh-server

RUN curl -o socket-activate.py "https://gitlab.com/dkg/socket-activate/-/raw/master/socket_activate/__main__.py?inline=false"
RUN chmod +x socket-activate.py

RUN cargo install --git https://gitlab.com/wiktor/pks-dummy.git --rev bfb4387

COPY Cargo.toml Cargo.lock /app/
WORKDIR /app
RUN mkdir .cargo
RUN mkdir src
RUN touch src/main.rs
RUN cargo vendor > .cargo/config

RUN rm src/main.rs
COPY src /app/src
RUN cargo build

COPY test.sh ssh-askpass.sh /app/
RUN ./test.sh
