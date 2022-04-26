#!/bin/bash

set -euxo pipefail

export SSH_ASKPASS=/app/ssh-askpass.sh

useradd testuser

mkdir -p /home/testuser/.ssh

echo test message > /home/testuser/message.txt

# sshd needs this directory or the following error is printed:
# "Missing privilege separation directory: /run/sshd"
mkdir -p /run/sshd

echo Starting SSH server...

# need to start with full path, otherwise the following error is printed:
# "sshd re-exec requires execution with an absolute path"
/usr/sbin/sshd

echo Starting PKS agent...

fingerprints=(
    # RSA 3k signing key
    "76BC8E72BE4AFBD528CE7AE9071A60B1FB52BFC8"
    # ed25519 signing key
    "FC119BC41CC2CE6A1C1B7B172ABC4D3B2C0DA477"
)

for key in "${fingerprints[@]}"; do
export PKS_SOCK=$(mktemp)
export SSH_AUTH_SOCK=$(mktemp)

/app/target/debug/ssh-agent-pks -H unix://$SSH_AUTH_SOCK &
sleep 1
ls -la /run

echo Starting PKS soft...
cat *.pgp > ../all-keys.pgp
mkdir -p /run/user/1000
pks-soft -H unix://$PKS_SOCK --secring ../all-keys.pgp &
sleep 1
ls -la /run/user/1000

echo Checking ssh-add...

#ssh-add -vvv -L

#ssh-add -s /
ssh-add -s /$key

ssh-add -L > /home/testuser/.ssh/authorized_keys

ssh -o "StrictHostKeyChecking=no" testuser@localhost cat /home/testuser/message.txt
done
