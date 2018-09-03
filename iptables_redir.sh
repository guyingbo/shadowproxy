# 在 nat 表中创建新链
iptables -t nat -N shadowsocks
# iptables -t nat -A shadowsocks -d {your_ip} -j RETURN

iptables -t nat -A shadowsocks -d 0.0.0.0/8 -j RETURN
iptables -t nat -A shadowsocks -d 10.0.0.0/8 -j RETURN
iptables -t nat -A shadowsocks -d 127.0.0.0/8 -j RETURN
iptables -t nat -A shadowsocks -d 169.254.0.0/16 -j RETURN
iptables -t nat -A shadowsocks -d 172.16.0.0/12 -j RETURN
iptables -t nat -A shadowsocks -d 192.168.0.0/16 -j RETURN
iptables -t nat -A shadowsocks -d 224.0.0.0/4 -j RETURN
iptables -t nat -A shadowsocks -d 240.0.0.0/4 -j RETURN
iptables -t nat -A shadowsocks -p tcp -j REDIRECT --to-ports 12345
# 12345 是 shadowsocks 的默认监听端口
iptables -t nat -I PREROUTING -p tcp -j shadowsocks
# 在 PREROUTING 链前插入 shadowsocks 链,使其生效
