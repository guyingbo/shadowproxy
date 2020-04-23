"""
An universal proxy server/client which support
Socks/HTTP/Shadowsocks/Redirect (tcp) and
Shadowsocks/TProxy/Tunnel (udp) protocols.

uri syntax:

{scheme}://[{userinfo}@][hostname]:{port}[/?[plugin={p;args}][via={uri}][target={t}]][#{fragment}]

userinfo = cipher:password or base64(cipher:password) when scheme is ss, ssudp
userinfo = username:password or base64(username:password) when scheme is socks, http.

supported protocols:

protocol        server  client  scheme
socks5          yes     yes     socks://
socks4          yes     yes     socks4://
ss              yes     yes     ss://
ss aead         yes     yes     ss://
http connect    yes     yes     http://
http forward    yes     yes     forward://
transparent     yes     no      red://

examples:

# http(s) proxy
shadowproxy -v http://:8527

# socks5 -> shadowsocks
shadowproxy -v 'socks://:8527/?via=ss://aes-256-cfb:password@127.0.0.1:8888'

# http   -> shadowsocks
shadowproxy -v 'http://:8527/?via=ss://aes-256-cfb:password@127.0.0.1:8888'

# redir  -> shadowsocks
shadowproxy -v 'red://:12345/?via=ss://aes-256-cfb:password@127.0.0.1:8888'

# shadowsocks server (tcp)
shadowproxy -v ss://aes-256-cfb:password@:8888

# shadowsocks server (udp)
shadowproxy -v ssudp://aes-256-cfb:password@:8527

# tunnel -> shadowsocks (udp)
shadowproxy -v \
    tunneludp://:8527/?target=8.8.8.8:53&via=ssudp://chacha20:pass@127.0.0.1:8888

# tproxy -> shadowsocks (udp)
sudo shadowproxy -v tproxyudp://:8527/?via=ssudp://chacha20:password@127.0.0.1:8888
"""
__version__ = "0.7.0"
