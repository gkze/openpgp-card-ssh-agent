<!--
SPDX-FileCopyrightText: 2021-2022 Wiktor Kwapisiewicz <wiktor@metacode.biz>
SPDX-FileCopyrightText: 2022 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Simple (experimental) standalone SSH Agent for OpenPGP cards

This is a simple SSH Agent that uses keys on OpenPGP cards. The cards are accessed via PC/SC (e.g. via `pcscd`).

The agent doesn't currently persist card identities or PINs.

## Install

```
$ cargo install openpgp-card-ssh-agent
```

## Run

```
$ openpgp-card-ssh-agent -H unix://$XDG_RUNTIME_DIR/ocsa.sock
```

## Use

List the available cards, e.g. with the `opgpcard` tool:

```
$ opgpcard list
Available OpenPGP cards:
 FFFE:01234567
```

If you don't see your card, it's possible that GnuPG is blocking it.
The easiest way to solve this is to unplug and replug the card.

Set the `SSH_AUTH_SOCK` environment variable:

```
$ export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/ocsa.sock
```

After freshly starting the agent, you need to add your card(s) to the agent once:

```
$ ssh-add -s FFFE:01234567
```

Enter the User PIN to the card (e.g. `123456`).
The agent will verify the User PIN. If the PIN is OK, it will remember both the card ident and the User PIN.

After adding a card, regular ssh usage backed by the authentication key slot on that card will work:

```
$ ssh <hostname>
```

# Credit

This project is based *very* heavily on work by Wiktor Kwapisiewicz <wiktor@metacode.biz>,
at https://gitlab.com/sequoia-pgp/ssh-agent-pks
