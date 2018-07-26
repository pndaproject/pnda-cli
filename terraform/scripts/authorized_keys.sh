#!/bin/sh
mkdir /home/cloud-user/.ssh
cat /tmp/scripts/key_name.pem.pub >> /home/cloud-user/.ssh/authorized_keys