"""
An universal proxy server/client which support
Socks5/HTTP/Shadowsocks/Redirect (tcp) and
Shadowsocks/TProxy/Tunnel (udp) protocols.

uri syntax:

{scheme}://[{userinfo}@][hostname]:{port}[/?[plugin={p;args}][via={uri}][target={t}]][#{fragment}]

userinfo = base64(cipher:password) when scheme is ss, ssudp
userinfo = base64(username:password) when scheme is socks, http or https.

support tcp schemes:
  scheme:   socks, ss, red, http, https
  via_scheme:  ss
support udp schemes:
  scheme:   ssudp, tproxyudp, tunneludp
  via_scheme:  ssudp

examples:
  # http(s) proxy
  shadowproxy -v http://:8527

  # socks5 --> shadowsocks
  shadowproxy -v socks://:8527/?via=ss://aes-256-cfb:password@127.0.0.1:8888

  # http   --> shadowsocks
  shadowproxy -v http://:8527/?via=ss://aes-256-cfb:password@127.0.0.1:8888

  # redir  --> shadowsocks
  shadowproxy -v red://:12345/?via=ss://aes-256-cfb:password@127.0.0.1:8888

  # shadowsocks server (tcp)
  shadowproxy -v ss://aes-256-cfb:password@:8888

  # shadowsocks server (udp)
  shadowproxy -v ssudp://aes-256-cfb:password@:8527

  # tunnel --> shadowsocks (udp)
  shadowproxy -v \
tunneludp://:8527/?target=8.8.8.8:53&via=ssudp://aes-256-cfb:password@127.0.0.1:8888

  # tproxy --> shadowsocks (udp)
  sudo shadowproxy -v \
tproxyudp://:8527/?via=ssudp://aes-256-cfb:password@127.0.0.1:8888
"""
__version__ = "0.3.0"
