#!/usr/bin/zsh
/sbin/sshd -d -p 1234 &
go run sshprobe.go
fg
