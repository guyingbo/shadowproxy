# Shadowproxy

[![Python package](https://github.com/guyingbo/shadowproxy/workflows/Python%20package/badge.svg?branch=master)](https://github.com/guyingbo/shadowproxy/actions/workflows/pythonpackage.yml)
[![Python Version](https://img.shields.io/pypi/pyversions/shadowproxy.svg)](https://pypi.python.org/pypi/shadowproxy)
[![Version](https://img.shields.io/pypi/v/shadowproxy.svg)](https://pypi.python.org/pypi/shadowproxy)
[![License](https://img.shields.io/pypi/l/shadowproxy.svg)](https://pypi.python.org/pypi/shadowproxy)
[![Lines Of Code](https://tokei.rs/b1/github/guyingbo/shadowproxy?category=code)](https://github.com/guyingbo/shadowproxy)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)

## Introduction

Shadowproxy is a versatile and high-performance proxy server written in Python. It implements a variety of TCP and UDP protocols, including Socks5, Shadowsocks, and HTTP. It is designed to be a lightweight and efficient replacement for other proxy tools like `ss-redir`, `ss-tunnel`, `ss-server`, and `ss-local`, consolidating their functionalities into a single, powerful command.

This project is built on top of the `curio` library, enabling it to handle thousands of concurrent connections with low overhead. It is inspired by `qwj/python-proxy` and aims to provide a flexible and extensible proxy solution.

## Features

*   **Multiple Protocols:** Supports a wide range of protocols for both TCP and UDP.
    *   **TCP:** Socks5, Socks4, Shadowsocks (including AEAD), HTTP (CONNECT and forward), and Transparent Proxy (`red`).
    *   **UDP:** Shadowsocks, TProxy, and Tunnel.
*   **Chainable Proxies:** You can chain multiple proxies together using the `via` parameter.
*   **Plugin System:** Extend the functionality of Shadowproxy with plugins for traffic obfuscation and other features.
*   **IPv6 Support:** Full support for both IPv4 and IPv6.
*   **High Performance:** Built with `curio` for asynchronous I/O, making it fast and scalable.
*   **Lightweight:** A single executable with a small footprint.

## Installation

Shadowproxy requires Python 3.6 or higher.

### From PyPI

You can install Shadowproxy directly from PyPI using `pip`:

```bash
pip3 install shadowproxy
```

### From Source

To install from the source, clone the repository and install it using `pip`:

```bash
git clone https://github.com/guyingbo/shadowproxy.git
cd shadowproxy
pip3 install .
```

## Usage

Shadowproxy is configured using a URI-based syntax. You can run one or more proxy servers with a single command.

### Command-Line Interface

```
usage: shadowproxy [-h] [-v] [--version] server [server ...]
```

### URI Syntax

The general format for a server URI is:

```
{scheme}://[{userinfo}@][hostname]:{port}[/?[plugin={p;args}][via={uri}][target={t}][source_ip={ip}]][#{fragment}]
```

*   `scheme`: The protocol to use (e.g., `socks`, `ss`, `http`).
*   `userinfo`: Authentication details.
    *   For `ss` and `ssudp`: `cipher:password` or `base64(cipher:password)`.
    *   For `socks` and `http`: `username:password` or `base64(username:password)`.
*   `hostname`: The address to bind to (e.g., `0.0.0.0`, `::`, `127.0.0.1`).
*   `port`: The port to listen on.
*   `plugin`: The plugin to use, with optional arguments.
*   `via`: The next proxy in the chain.
*   `target`: The destination address for tunnel proxies.
*   `source_ip`: The source IP address for outgoing connections.
*   `fragment`: Used for SSL certificate and key files (`keyfile,certfile`).

### Examples

#### Simple Shadowsocks Server

To start a simple Shadowsocks server on port 8888 with the `chacha20` cipher:

```bash
shadowproxy ss://chacha20:password@0.0.0.0:8888
```

To bind to an IPv6 address:

```bash
shadowproxy ss://chacha20:password@[::]:8888
```

#### Chained Proxies

To chain a Socks5 proxy to a Shadowsocks proxy:

```bash
# Listen as a Socks5 proxy on port 8527 and forward traffic to a Shadowsocks server
shadowproxy -v socks://:8527/?via=ss://aes-256-cfb:password@127.0.0.1:8888
```

You can do the same with an HTTP proxy:

```bash
shadowproxy -v http://:8527/?via=ss://aes-256-cfb:password@127.0.0.1:8888
```

#### Transparent Proxy

To set up a transparent proxy (you will also need to configure `iptables`):

```bash
shadowproxy -v red://:12345/?via=ss://aes-256-cfb:password@127.0.0.1:8888
```

#### UDP Tunnels

To create a UDP tunnel for DNS queries:

```bash
# Listen for UDP on port 8527, forward to 8.8.8.8:53 through a Shadowsocks server
shadowproxy -v tunneludp://:8527/?target=8.8.8.8:53&via=ssudp://aes-256-cfb:password@127.0.0.1:8888
```

## Protocols

| Protocol          | Server | Client | Scheme        |
| ----------------- | :----: | :----: | ------------- |
| Socks5            |   ✓    |   ✓    | `socks://`    |
| Socks4            |   ✓    |   ✓    | `socks4://`   |
| Shadowsocks       |   ✓    |   ✓    | `ss://`       |
| Shadowsocks AEAD  |   ✓    |   ✓    | `ss://`       |
| HTTP CONNECT      |   ✓    |   ✓    | `http://`     |
| HTTP Forward      |        |   ✓    | `forward://`  |
| Transparent Proxy |   ✓    |        | `red://`      |
| UDP Tunnel        |   ✓    |        | `tunneludp://`|
| Shadowsocks UDP   |   ✓    |   ✓    | `ssudp://`    |

## Ciphers

Shadowproxy supports a variety of stream and AEAD ciphers:

*   `aes-256-cfb`
*   `aes-128-cfb`
*   `aes-192-cfb`
*   `chacha20`
*   `salsa20`
*   `rc4`
*   `chacha20-ietf-poly1305`
*   `aes-256-gcm`
*   `aes-192-gcm`
*   `aes-128-gcm`

## Plugins

Plugins can be used to obfuscate traffic and add other features.

| Plugin               | Server | Client |
| -------------------- | :----: | :----: |
| `http_simple`        |   ✓    |   ✓    |
| `tls1.2_ticket_auth` |   ✓    |   ✓    |

### `http_simple`

The `http_simple` plugin obfuscates traffic by making it look like a simple HTTP request.

**Example:**

```bash
# Server
shadowproxy ss://chacha20:password@0.0.0.0:8888/?plugin=http_simple

# Client
shadowproxy socks://:8527/?via=ss://chacha20:password@server_ip:8888/?plugin=http_simple
```

### `tls1.2_ticket_auth`

The `tls1.2_ticket_auth` plugin mimics a TLS 1.2 handshake to disguise the traffic as HTTPS.

**Example:**

```bash
# Server
shadowproxy ss://chacha20:password@0.0.0.0:8888/?plugin=tls1.2_ticket_auth

# Client
shadowproxy socks://:8527/?via=ss://chacha20:password@server_ip:8888/?plugin=tls1.2_ticket_auth
```

## Docker

You can also run Shadowproxy using Docker.

### From Docker Hub

To run the pre-built image from Docker Hub:

```bash
docker run -it --rm -p 8000:8527 tensiongyb/shadowproxy -vv socks://:8527
```

### Building the Image

To build the Docker image from the source:

```bash
docker build -t shadowproxy .
```

Then you can run your local image:

```bash
docker run -it --rm -p 8000:8527 shadowproxy -vv socks://:8527
```