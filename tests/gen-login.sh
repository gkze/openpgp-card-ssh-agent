#!/bin/bash

export CARD=$1
export ALGO=$2

echo "Testing on $CARD with $ALGO"
opgpcard admin --card "$CARD" -P /dev/fd/3 generate -p /dev/fd/4 --output /dev/null "$ALGO" 3<<<12345678 4<<<123456
opgpcard ssh --key-only > /home/testuser/.ssh/authorized_keys
cat /home/testuser/.ssh/authorized_keys
expect tests/ssh-add.exp "$CARD"
ssh -o "StrictHostKeyChecking=no" testuser@localhost id
echo
