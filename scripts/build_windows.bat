@echo off
set GOOS=windows
set GOARCH=amd64
go build -o builds/kiroctl.exe
