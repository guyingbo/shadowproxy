# Shadowproxy

[![Build Status](https://travis-ci.org/guyingbo/shadowproxy.svg?branch=master)](https://travis-ci.org/guyingbo/shadowproxy)

## Intro

Proxy server that implements Socks5/Shadowsocks/Redirect/HTTP (tcp) and Shadowsocks/TProxy/Tunnel (udp) protocols.

Thanks to Dabeaz's awesome curio project: https://github.com/dabeaz/curio

This project is inspired by qwj's python-proxy project(https://github.com/qwj/python-proxy), and some part of http proxy code was copy from it.


It is a replacement of shadowsocks and shadowsocks-libev, one can replace ss-redir, ss-tunnel, ss-server, ss-local with shadowproxy.py

## Usage

```
usage: shadowproxy.py [-h] [-v] [--version] [--monitor] server [server ...]

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
python3.6 %(prog)s -v socks://:8527=ssr://aes-256-cfb:password@127.0.0.1:8888

# http   --> shadowsocks
python3.6 %(prog)s -v http://:8527=ssr://aes-256-cfb:password@127.0.0.1:8888

# https  --> shadowsocks
python3.6 %(prog)s -v https://:8527#keyfile,certfile=ssr://aes-256-cfb:password@127.0.0.1:8888

# redir  --> shadowsocks
python3.6 %(prog)s -v red://:12345=ssr://aes-256-cfb:password@127.0.0.1:8888

# shadowsocks server (tcp)
python3.6 %(prog)s -v ss://aes-256-cfb:password@:8888

# shadowsocks server (udp)
python3.6 %(prog)s -v ssudp://aes-256-cfb:password@:8527

# tunnel --> shadowsocks (udp)
python3.6 %(prog)s -v tunneludp://:8527#8.8.8.8:53=ssrudp://aes-256-cfb:password@127.0.0.1:8888

# tproxy --> shadowsocks (udp)
sudo python3.6 %(prog)s -v tproxyudp://:8527=ssrudp://aes-256-cfb:password@127.0.0.1:8888
```

## Installation

install latest version of curio on github: https://github.com/dabeaz/curio
```
pip3.6 install pylru
```
