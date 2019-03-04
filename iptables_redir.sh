# 创建一个 nat 类型的新表，然后插入到prerouting链中。
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
# 将目的地为1.1.1.1的tcp流量应用shadowsocks表的规则
iptables -t nat -I PREROUTING -p tcp -d 1.1.1.1/32 -j shadowsocks
# iptables -t nat -I PREROUTING -p tcp -j shadowsocks
# 在 PREROUTING 链前部插入 shadowsocks 表,使其生效
