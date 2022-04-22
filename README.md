# SSH Agent using PKS

This is an SSH Agent that uses keys exposed via the [Private Key
Store][PKS] protocol. Currently supported and used daily is a backend
that allows using OpenPGP Card smartcards.

[PKS]: https://gitlab.com/sequoia-pgp/pks

## Running

First you need a PKS backend server, the recommended on is https://gitlab.com/sequoia-pgp/pks-openpgp-card

For convenience first export the socket path that will be used by
OpenSSH tools:

```
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/ssh-agent-pks.sock
```

Then run this project binding to the socket while also specifying
backend server:

```
cargo run -- -H unix://$SSH_AUTH_SOCK --endpoint $XDG_RUNTIME_DIR/pks-openpgp-card.sock
```

List the available keys with:

```
$ curl --unix-socket $XDG_RUNTIME_DIR/pks-openpgp-card.sock localhost:3000/keys
E7E2B84A36457BEA3F43692DE68BE3B312FA33FC # 0006:15422467 S
F99A81E09CD8814B571DBF4AEB0BE68CD9CF08F1 # 0006:15422467 E
3BA4FE02BF714A7789CB2E0051F23D6C0529CE0A # 0006:15422467 A
```

If you don't see any keys it's possible that GnuPG is blocking the
cards. The easiest way to solve this is to unplug and plug the card
again.

Next, you need to add your key to the agent:

```
ssh-add -s /3BA4FE02BF714A7789CB2E0051F23D6C0529CE0A
```

Enter the PIN to the card. The agent will verify that and if it's OK
add the key (in reality it will get the capability URL and memorize
that, not the PIN).

and then the regular ssh will work:

```
ssh ...
```

## Production use

It is recommended to use systemd socket activation to run the
server. See `contrib` directory for details.

Packages:
  - https://aur.archlinux.org/packages/ssh-agent-pks-git
