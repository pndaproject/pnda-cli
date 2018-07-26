#!/bin/sh
adduser cloud-user
passwd -d cloud-user
echo "%cloud-user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/cloud-user
