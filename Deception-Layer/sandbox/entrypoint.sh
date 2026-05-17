#!/bin/sh
# Start the audit daemon in the background
auditd || true
# Start the SSH daemon in the foreground so the container stays alive
exec /usr/sbin/sshd -D -p 2222
