# PKS SSH Agent

You need a PKS implementation for example this: https://gitlab.com/wiktor/pks-openpgp-card to be running.

Then `cargo run` this one. The socket will be at `/tmp/pks-ssh-agent`.

For the sake of the example set the env variable:
```
export SSH_AUTH_SOCK=/tmp/pks-ssh-agent
```

Next, you need to add your key to the agent:


```
ssh-add -s http://localhost:3000/3BA4FE02BF714A7789CB2E0051F23D6C0529CE0A
```

The key fingerprint must point to the authorization key. You can get it via:

```
gpg -K --with-subkey-fingerprints
```

Enter the PIN to the card. The agent will verify that and if it's OK add the key (in reality it will get the capability URL and memorize that).

and then the regular ssh will work:

```
ssh ...
```
