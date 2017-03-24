# Shadowproxy

[![Build Status](https://travis-ci.org/guyingbo/shadowproxy.svg?branch=master)](https://travis-ci.org/guyingbo/shadowproxy)

## Intro

A proxy server that implements Socks5/Shadowsocks/Redirect/HTTP (tcp) and Shadowsocks/TProxy/Tunnel (udp) protocols.

Thanks to Dabeaz's awesome curio project: https://github.com/dabeaz/curio

This project is inspired by qwj's python-proxy project(https://github.com/qwj/python-proxy), and some part of http proxy code was copy from it.


It is a replacement of shadowsocks and shadowsocks-libev, one can replace ss-redir, ss-tunnel, ss-server, ss-local with shadowproxy.py

## Usage

```
usage: shadowproxy [-h] [-v] [--version] [--monitor] server [server ...]

uri syntax: {local_scheme}://[cipher:password@]{netloc}[#fragment][{=remote_scheme}://[cipher:password@]{netloc}]

support tcp schemes:
  local_scheme:   socks, ss, red, http, https
  remote_scheme:  ssr
support udp schemes:
  local_scheme:   ssudp, tproxyudp, tunneludp
  remote_scheme:  ssrudp
```

examples:

```
# socks5 --> shadowsocks
shadowproxy -v socks://:8527=ssr://aes-256-cfb:password@127.0.0.1:8888

# http   --> shadowsocks
shadowproxy -v http://:8527=ssr://aes-256-cfb:password@127.0.0.1:8888

# https  --> shadowsocks
shadowproxy -v https://:8527#keyfile,certfile=ssr://aes-256-cfb:password@127.0.0.1:8888

# redir  --> shadowsocks
shadowproxy -v red://:12345=ssr://aes-256-cfb:password@127.0.0.1:8888

# shadowsocks server (tcp)
shadowproxy -v ss://aes-256-cfb:password@:8888

# shadowsocks server (udp)
shadowproxy -v ssudp://aes-256-cfb:password@:8527

# tunnel --> shadowsocks (udp)
shadowproxy -v tunneludp://:8527#8.8.8.8:53=ssrudp://aes-256-cfb:password@127.0.0.1:8888

# tproxy --> shadowsocks (udp)
shadowproxy -v tproxyudp://:8527=ssrudp://aes-256-cfb:password@127.0.0.1:8888
```

## Installation

shadowproxy requires Python3.6.

```
pip install shadowproxy
```
