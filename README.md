# Shadowproxy

[![Build Status](https://travis-ci.org/guyingbo/shadowproxy.svg?branch=master)](https://travis-ci.org/guyingbo/shadowproxy)
[![Python Version](https://img.shields.io/pypi/pyversions/shadowproxy.svg)](https://pypi.python.org/pypi/shadowproxy)
[![Version](https://img.shields.io/pypi/v/shadowproxy.svg)](https://pypi.python.org/pypi/shadowproxy)
[![Format](https://img.shields.io/pypi/format/shadowproxy.svg)](https://pypi.python.org/pypi/shadowproxy)
[![License](https://img.shields.io/pypi/l/shadowproxy.svg)](https://pypi.python.org/pypi/shadowproxy)
[![Code Coverage](https://codecov.io/gh/guyingbo/shadowproxy/branch/master/graph/badge.svg)](https://codecov.io/gh/guyingbo/shadowproxy)
[![Lines Of Code](https://tokei.rs/b1/github/guyingbo/shadowproxy?category=code)](https://github.com/guyingbo/shadowproxy)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)


## Introduction

A proxy server that implements Socks5/Shadowsocks/Redirect/HTTP (tcp) and Shadowsocks/TProxy/Tunnel (udp) protocols.

Thanks to Dabeaz's awesome [curio](https://github.com/dabeaz/curio) project.

This project is inspired by qwj's [python-proxy](https://github.com/qwj/python-proxy) project.

It is a replacement of shadowsocks and shadowsocks-libev, you can replace ss-redir, ss-tunnel, ss-server, ss-local with just one shadowproxy command.

## Installation

shadowproxy requires Python3.6+

```
pip3 install shadowproxy
```

## Features

### supported protocols

protocol | server | client | scheme
--- | --- | --- | ---
socks5 | ✓ | ✓ | socks://
socks4 | ✓ | ✓ | socks4://
ss | ✓ | ✓ | ss://
ss aead | ✓ | ✓ | ss://
http connect | ✓ | ✓ | http://
http forward |  | ✓ | forward://
transparent proxy | ✓ | | red://
tunnel(udp) | ✓ | | tunneludp://
ss(udp) | ✓ | ✓ | ssudp://

### supported plugins

plugin | server | client
--- | --- | ---
http_simple | ✓ | ✓
tls1.2_ticket_auth | ✓ | ✓

### supported ciphers

* aes-256-cfb
* aes-128-cfb
* aes-192-cfb
* chacha20
* salsa20
* rc4
* chacha20-ietf-poly1305
* aes-256-gcm
* aes-192-gcm
* aes-128-gcm

### other features

* support both IPv4 and IPv6

Here are some ipv6 url examples:

```
http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80/index.html
http://[1080:0:0:0:8:800:200C:417A]/index.html
http://[3ffe:2a00:100:7031::1]
http://[1080::8:800:200C:417A]/foo
http://[::192.9.5.5]/ipng
http://[::FFFF:129.144.52.38]:80/index.html
http://[2010:836B:4179::836B:4179]
```

## Usage

```
usage: shadowproxy [-h] [-v] [--version] server [server ...]

uri syntax:

{scheme}://[{userinfo}@][hostname]:{port}[/?[plugin={p;args}][via={uri}][target={t}][source_ip={ip}]][#{fragment}]

userinfo = cipher:password or base64(cipher:password) when scheme is ss, ssudp
userinfo = username:password or base64(username:password) when scheme is socks, http.

```

examples:

```
# simple shadowsocks server
shadowproxy ss://chacha20:password@0.0.0.0:8888

# ipv6 binding
shadowproxy ss://chacha20:password@[::]:8888

# socks5 --> shadowsocks
shadowproxy -v socks://:8527/?via=ss://aes-256-cfb:password@127.0.0.1:8888

# http   --> shadowsocks
shadowproxy -v http://:8527/?via=ss://aes-256-cfb:password@127.0.0.1:8888

# redir  --> shadowsocks
shadowproxy -v red://:12345/?via=ss://aes-256-cfb:password@127.0.0.1:8888

# shadowsocks server (udp)
shadowproxy -v ssudp://aes-256-cfb:password@:8527

# tunnel --> shadowsocks (udp)
shadowproxy -v tunneludp://:8527/?target=8.8.8.8:53&via=ssudp://aes-256-cfb:password@127.0.0.1:8888

# tproxy --> shadowsocks (udp)
shadowproxy -v tproxyudp://:8527/?via=ssudp://aes-256-cfb:password@127.0.0.1:8888
```
