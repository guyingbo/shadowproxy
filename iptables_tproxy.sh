ip rule add fwmark 0x01/0x01 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
iptables -t mangle -A PREROUTING -d {remote_ip} -p udp -j RETURN
iptables -t mangle -A PREROUTING -d 0.0.0.0/8 -p udp -j RETURN
iptables -t mangle -A PREROUTING -d 10.0.0.0/8 -p udp -j RETURN
iptables -t mangle -A PREROUTING -d 127.0.0.0/8 -p udp -j RETURN
iptables -t mangle -A PREROUTING -d 169.254.0.0/16 -p udp -j RETURN
iptables -t mangle -A PREROUTING -d 172.16.0.0/12 -p udp -j RETURN
iptables -t mangle -A PREROUTING -d 192.168.0.0/16 -p udp -j RETURN
iptables -t mangle -A PREROUTING -d 224.0.0.0/4 -p udp -j RETURN
iptables -t mangle -A PREROUTING -d 240.0.0.0/4 -p udp -j RETURN
iptables -t mangle -A PREROUTING -p udp -j TPROXY --tproxy-mark 0x01/0x01 --on-port 12345
#iptables -t mangle -A OUTPUT -p udp --dport 53 -j MARK --set-mark 1
