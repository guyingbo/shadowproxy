# Shadowproxy

## Intro

Proxy server that implements tcp: Socks5/HTTP/Shadowsocks/Redirect udp: TProxy/Tunnel protocols.

It is a replacement of shadowsocks and shadowsocks-libev, one can replace ss-redir, ss-tunnel, ss-server, ss-local with shadowproxy.py

## Usage

```
examples:
  python3.6 %(prog)s -v socks://:8527=ssr://aes-256-cfb:password@127.0.0.1:8888                     # socks5 --> shadowsocks
  python3.6 %(prog)s -v http://:8527=ssr://aes-256-cfb:password@127.0.0.1:8888                      # http   --> shadowsocks
  python3.6 %(prog)s -v red://:12345=ssr://aes-256-cfb:password@127.0.0.1:8888                      # redir  --> shadowsocks
  python3.6 %(prog)s -v ss://aes-256-cfb:password@:8888                                             # shadowsocks server (tcp)
  python3.6 %(prog)s -v ssudp://aes-256-cfb:password@:8527                                          # shadowsocks server (udp)
  python3.6 %(prog)s -v tunneludp://:8527#8.8.8.8:53=ssrudp://aes-256-cfb:password@127.0.0.1:8888   # tunnel --> shadowsocks (udp)
  sudo python3.6 %(prog)s -v tproxyudp://:8527=ssrudp://aes-256-cfb:password@127.0.0.1:8888         # tproxy --> shadowsocks (udp)
```

## Installation

install latest version of curio on github: https://github.com/dabeaz/curio
```
pip3.6 install pylru
```
