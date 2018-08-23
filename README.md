# Shadowproxy

[![Build Status](https://travis-ci.org/guyingbo/shadowproxy.svg?branch=master)](https://travis-ci.org/guyingbo/shadowproxy)
[![Python Version](https://img.shields.io/pypi/pyversions/shadowproxy.svg)](https://pypi.python.org/pypi/shadowproxy)
[![Version](https://img.shields.io/pypi/v/shadowproxy.svg)](https://pypi.python.org/pypi/shadowproxy)
[![Format](https://img.shields.io/pypi/format/shadowproxy.svg)](https://pypi.python.org/pypi/shadowproxy)
[![License](https://img.shields.io/pypi/l/shadowproxy.svg)](https://pypi.python.org/pypi/shadowproxy)
[![codecov](https://codecov.io/gh/guyingbo/shadowproxy/branch/master/graph/badge.svg)](https://codecov.io/gh/guyingbo/shadowproxy)


## Intro

A proxy server that implements Socks5/Shadowsocks/Redirect/HTTP (tcp) and Shadowsocks/TProxy/Tunnel (udp) protocols.

Thanks to Dabeaz's awesome curio project: https://github.com/dabeaz/curio

This project is inspired by qwj's python-proxy project(https://github.com/qwj/python-proxy), and some part of http proxy code was copy from it.


It is a replacement of shadowsocks and shadowsocks-libev, you can replace ss-redir, ss-tunnel, ss-server, ss-local with shadowproxy.py

## Usage

```
usage: shadowproxy [-h] [-v] [--version] [--monitor] server [server ...]

uri syntax: {server_scheme}://[cipher:password@]{netloc}[#fragment][{=client_scheme}://[cipher:password@]{netloc}]

support tcp schemes:
  server_scheme: socks, ss, red, http, https
  client_scheme: ss, http
support udp schemes:
  server_scheme: ssudp, tproxyudp, tunneludp
  client_scheme: ssudp
```

examples:

```
# socks5 --> shadowsocks
shadowproxy -v socks://:8527=ss://aes-256-cfb:password@127.0.0.1:8888

# http   --> shadowsocks
shadowproxy -v http://:8527=ss://aes-256-cfb:password@127.0.0.1:8888

# https  --> shadowsocks
shadowproxy -v https://:8527#keyfile,certfile=ss://aes-256-cfb:password@127.0.0.1:8888

# redir  --> shadowsocks
shadowproxy -v red://:12345=ss://aes-256-cfb:password@127.0.0.1:8888

# shadowsocks server (tcp)
shadowproxy -v ss://aes-256-cfb:password@:8888

# shadowsocks server (udp)
shadowproxy -v ssudp://aes-256-cfb:password@:8527

# tunnel --> shadowsocks (udp)
shadowproxy -v tunneludp://:8527#8.8.8.8:53=ssudp://aes-256-cfb:password@127.0.0.1:8888

# tproxy --> shadowsocks (udp)
shadowproxy -v tproxyudp://:8527=ssudp://aes-256-cfb:password@127.0.0.1:8888
```

## Installation

shadowproxy requires Python3.6+

```
pip install shadowproxy
```

## Features

### supported protocols

protocol | server | client | scheme
--- | --- | --- | ---
socks5 | ✓ | ✓ | socks://
socks4 | | ✓ | socks4://
ss | ✓ | ✓ | ss://
ss aead | ✓ | ✓ | ss://
http | ✓ | ✓ | httponly://
http connect(tunnel) | ✓ | ✓ | http://
transparent proxy | ✓ | | red://

### supported plugins

plugin | server | client
--- | --- | ---
http_simple | ✓ | ✓
tls1.2_ticket_auth | ✓ |

### supported ciphers

* aes-256-cfb
* aes-128-cfb
* aes-192-cfb
* chacha20
* salsa20
* rc4
* aes-256-gcm
* aes-192-gcm
* aes-128-gcm
