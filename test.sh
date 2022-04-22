#!/bin/bash


# sshd needs this directory or the following error is printed:
# "Missing privilege separation directory: /run/sshd"
mkdir -p /run/sshd

echo Starting SSH server...

# need to start with full path, otherwise the following error is printed:
# "sshd re-exec requires execution with an absolute path"
/usr/sbin/sshd

echo Starting PKS agent...

export PKS_SOCK=/run/user/1000/pks-dummy.sock

/app/target/debug/ssh-agent-pks -H unix:///run/ssh-agent-pks.sock &
sleep 1
ls -la /run

echo Starting PKS dummy...
mkdir -p /run/user/1000
pks-dummy &
sleep 1
ls -la /run/user/1000

echo Checking ssh-add...

export SSH_AUTH_SOCK=/run/ssh-agent-pks.sock
export SSH_ASKPASS=/app/ssh-askpass.sh

ssh-add -vvv -L

ssh-add -s /xxxx
