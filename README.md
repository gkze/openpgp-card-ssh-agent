<!--
SPDX-FileCopyrightText: 2021-2022 Wiktor Kwapisiewicz <wiktor@metacode.biz>
SPDX-FileCopyrightText: 2022-2024 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Simple standalone SSH Agent for OpenPGP cards

[![crates-io-badge](https://img.shields.io/crates/v/openpgp-card-ssh-agent.svg)](https://crates.io/crates/openpgp-card-ssh-agent)
[![status-badge](https://ci.codeberg.org/api/badges/openpgp-card/ssh-agent/status.svg)](https://ci.codeberg.org/openpgp-card/ssh-agent)

This is a simple SSH agent that uses keys on OpenPGP cards. Cards are accessed via PC/SC (e.g. via `pcscd`).

The agent currently supports RSA 2048/4096, NIST P-256/384/521 and Curve 25519 keys.

This agent relies on [openpgp-card-state](https://crates.io/crates/openpgp-card-state) for OpenPGP card User PIN
handling.

## Development status

This ssh-agent works, and you can use it right now.

However, it's in an early development stage. We might break things temporarily, in the course of development.

(E.g.: Windows support is currently broken in the 0.2 series, while `openpgp-card-state` is limited
to `org.freedesktop.Secret` as a secrets storage backend.)

## Install

This branch of openpgp-card-ssh-auth is still unreleased and can be installed from source by running:

```
$ cargo install --path .
```

## Persisting your OpenPGP card's User PIN

See [openpgp-card-state](https://crates.io/crates/openpgp-card-state) for more details.

To use an OpenPGP card with this ssh-agent, the User PIN for the card needs to be persisted via `openpgp-card-state` (
currently, only org.freedesktop.Secret is supported as a backend, and a provider of this service must be running).

A card PIN can then be persisted by running the equivalent of the following call for your card:

```
$ openpgp-card-state put 0000:01234567 123456
```

You need to pass card's User PIN instead of `123456`, and your card's "ident" instead of `0000:01234567` (one way to
find out your card's identy is to run [`oct list`](https://codeberg.org/openpgp-card/openpgp-card-tools#list-cards))

(Please consider if it's a problem if you leave a copy of your PIN in your shell history. And take steps to avoid it, if
so!)

## Running the ssh agent

```
$ openpgp-card-ssh-agent -H unix://$XDG_RUNTIME_DIR/ocsa.sock
```

To debug the operation of the agent, you can view debug output, e.g. by running it like this:

```
$ RUST_LOG=debug openpgp-card-ssh-agent -H unix://$XDG_RUNTIME_DIR/ocsa.sock
```

## Use

To use this ssh-agent, you need to set the `SSH_AUTH_SOCK` environment variable:

```
$ export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/ocsa.sock
```

After that, regular ssh usage will work and automatically use any available OpenPGP cards for authentication:

```
$ ssh <hostname>
```

Besides OpenPGP card User PINs, this agent doesn't require any configuration or state. Any card can be plugged in and
will be used automatically if the public key material in its authentication key slot is requested for signing by ssh.

Cards that are plugged in after that ssh-agent is started will be automatically found during the next operation.

### Troubleshooting

Note that GnuPG may lock cards by default. This can prevent other software, like this ssh-agent from accessing a card.
Killing the `scdaemon` process (which handles smart card access for GnuPG) is a simple way to debug problems with card
access.

## Notifications for touch confirmation

This SSH agent uses the [notify-rust](https://crates.io/crates/notify-rust) crate to alert the user if the card requires
touch confirmation.

To build without the notification mechanism (not recommended), you can use the `--no-default-features` parameter.

# Credit

This project is based *very* heavily on work by Wiktor Kwapisiewicz <wiktor@metacode.biz>.