<!--
SPDX-FileCopyrightText: 2021-2022 Wiktor Kwapisiewicz <wiktor@metacode.biz>
SPDX-FileCopyrightText: 2022-2024 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Simple standalone SSH Agent for OpenPGP cards

[![crates-io-badge](https://img.shields.io/crates/v/openpgp-card-ssh-agent.svg)](https://crates.io/crates/openpgp-card-ssh-agent)
[![status-badge](https://ci.codeberg.org/api/badges/openpgp-card/ssh-agent/status.svg)](https://ci.codeberg.org/openpgp-card/ssh-agent)

This is a simple SSH agent that uses keys on OpenPGP cards. Cards are accessed via PC/SC (e.g. via `pcscd`).

The agent currently supports RSA 2048/3072/4096, NIST P-256/384/521 and Curve 25519 keys.

This agent relies on [openpgp-card-state](https://crates.io/crates/openpgp-card-state) for OpenPGP card User PIN
handling.

## Development status

This ssh-agent works, and you can use it right now.

However, it's in an early development stage. We might break things temporarily, in the course of development.

## Install

You can install the latest openpgp-card-ssh-agent from crates.io by running

```
$ cargo install openpgp-card-ssh-agent
```

Or from this repository, by checking out the code and running:

```
$ cargo install --path .
```

## Persisting your OpenPGP card's User PIN

This ssh-agent uses [OpenPGP card](https://en.wikipedia.org/wiki/OpenPGP_card) hardware to perform private key
cryptographic operations. These cards require a User PIN to authorize operations.

This ssh-agent assumes that the User PIN for your card is persisted on your host computer, and that the PIN can be
obtained by the ssh-agent. Ideally without requiring any user-interaction.

OpenPGP card User PINs are stored in a platform-specific secrets storage mechanism. Those stores are long-term
persistent, so it is typically sufficient to persist a User PIN once per machine.

See [openpgp-card-state](https://crates.io/crates/openpgp-card-state) for more details.

### Listing OpenPGP cards

To see which OpenPGP cards are connected to your machine and can be used with the ssh agent, you can use the `ssh-add`
command to obtain a list from the ssh-agent, like this:

```
$ ssh-add -L
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFKjA9vr4sa4WznatwBo05LrmZ2jogj3fyrQ5hNLYsFT 0000:01234567
```

The output shows the public key material in your card's authentication key slot (shown in OpenSSH format), and the
card's identifier (here: `0000:01234567`). You can use that identifier to store the User PIN, as described in the next
section (using `ssh-add -s 0000:01234567`).

Note that this list doesn't indicate if a PIN has been stored for a card, already.

### Storing the User PIN with ssh-add

To store a card's User PIN on your system, you can use the `ssh-add` command and provide the card's "ident" (in this
example: `0000:01234567`):

```
$ ssh-add -s 0000:01234567
Enter passphrase for PKCS#11:
```

The message says that a "passphrase for PKCS#11" should be entered. This is inapplicable and confusing, when using this
ssh-agent. However, this string is hard coded in ssh and the wording of this message can be safely ignored.

At this prompt you can enter the User PIN (the default User PIN for many OpenPGP cards is `123456`). The PIN will get
tested on the card, and persisted if the card accepts it as valid.

## Running the ssh agent

```
$ openpgp-card-ssh-agent -H unix://$XDG_RUNTIME_DIR/ocsa.sock
```

To debug the operation of the agent, you can view debug output, e.g. by running it like this:

```
$ RUST_LOG=debug openpgp-card-ssh-agent -H unix://$XDG_RUNTIME_DIR/ocsa.sock
```

On Windows, use the following format to use a Named Pipe:

```
$ openpgp-card-ssh-agent -H \\.\pipe\ocsa
```

### Use with systemd

Config files for using `openpgp-card-ssh-agent` with systemd are provided in the `contrib` directory.

## Use

To use this ssh-agent, you need to set the `SSH_AUTH_SOCK` environment variable:

```
$ export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/ocsa.sock
```

Or, on Windows, set the variable to the Named Pipe:

```
set SSH_AUTH_SOCK=\\.\pipe\ocsa
```

After that, regular ssh usage will work and automatically use any available OpenPGP cards for authentication:

```
$ ssh <hostname>
```

Besides OpenPGP card User PINs, this agent doesn't require any configuration or state. Any card can be plugged in and
will be used automatically if the public key material in its authentication key slot is requested for signing by ssh.

Cards that are plugged in after that ssh-agent is started will be automatically found during the next operation.

### Troubleshooting

#### Problems with access to OpenPGP card devices

GnuPG may lock cards by default. This can prevent other software, like this ssh-agent from accessing a card.
Killing the `scdaemon` process (which handles smart card access for GnuPG) is a simple way to debug problems with card
access.

#### Git for Windows

Git access over SSH on Windows may fail to work with this ssh agent. If so, the cause is typically that Git on Windows
comes with a bundled OpenSSH client which does not support Named Pipes.

To resolve this, you should switch to use the "Windows native implementation of OpenSSH"
by [selecting the appropriate option](https://stackoverflow.com/a/71190226) during installation of Git for Windows.

## Notifications for touch confirmation

This SSH agent uses the [notify-rust](https://crates.io/crates/notify-rust) crate to alert the user if the card requires
touch confirmation.

To build without the notification mechanism (not recommended), you can use the `--no-default-features` parameter.

# Credit

This project is based *very* heavily on work by [Wiktor Kwapisiewicz](https://metacode.biz/@wiktor). Much of the heavy
ssh lifting
is happening in [ssh-agent-lib](https://crates.io/crates/ssh-agent-lib).
