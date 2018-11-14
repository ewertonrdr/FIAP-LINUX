#!/bin/sh

echo " Tabela de Conexões DIR: /proc/net/nf_conntrack"
clear

echo "***[[ Host Firewall Started ]]***"
ipt="iptables"
iface="ens33"
inet="192.168.229.0/24"

echo "DESCARREGANDO REGRAS PRÉ-EXISTENTES"
$ipt -F && echo "Regras Pré Existentes Descarregadas"
$ipt -X && echo "Regras Usuário Descarregadas"

echo "POLÍTICAS PADRÃO DE ACESSO"
$ipt -P INPUT DROP && echo "POLÍTICA PADRÃO DE BLOQUEIO TRÁFEGO ENTRANTE - IN" 
$ipt -P OUTPUT DROP && echo "POLÍTICA PADRÃO DE BLOQUEIO TRÁFEGO SAINTE - OUT"
$ipt -P FORWARD DROP && echo "POLÍTICA PADRÃO DE BLOQUEIO TRÁFEGO ENCAMINHADO - FORWARD"

echo "ATIVANDO MODO STATEFUL"
$ipt -A OUTPUT -o $iface -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$ipt -A INPUT -i $iface -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "REGRAS LOOPBACK"
$ipt -A INPUT -i lo -s 127.0.0.0/8 -j ACCEPT
$ipt -A OUTPUT -o lo  -j ACCEPT

echo "REGRAS ICMP"
$ipt -A OUTPUT -p icmp -j LOG --log-prefix "ICMP_OUT: " --log-level info
$ipt -A INPUT -p icmp -j LOG --log-prefix "ICMP_IN: " --log-level info

$ipt -A OUTPUT -o $iface -d 192.168.229.1 -p icmp --icmp-type echo-request -j ACCEPT
$ipt -A INPUT -i $iface -s 192.168.229.1 -p icmp --icmp-type echo-request -m limit --limit 4/second --limit-burst 4 -j ACCEPT

echo "REGRAS ANTI SMURF"
$ipt -A INPUT -p icmp -m icmp --icmp-type echo-request -m pkttype --pkt-type broadcast  -j DROP
$ipt -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
$ipt -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP

echo "REGRAS ANTI BROADCAST E MULTICAST"
$ipt -A INPUT -m pkttype --pkt-type broadcast -j LOG --log-prefix "BROADCAST :" --log-level info
$ipt -A INPUT -m pkttype --pkt-type multicast -j LOG --log-prefix "BROADCAST :" --log-level info

echo "REGRAS DE ACESSO SSH"
$ipt -A INPUT -p tcp --dport 22 -j LOG --log-prefix "SSH_IN: " --log-level info
$ipt -A INPUT -i $iface -s 192.168.229.1 -p tcp --dport 22 --syn -m state --state NEW,ESTABLISHED,RELATED -m mac --mac-source 00:50:56:C0:00:08 -j ACCEPT

$ipt -A OUTPUT -p tcp --sport 22 -j LOG --log-prefix "SSH_OUT: " --log-level info
$ipt -A OUTPUT -o $iface -d 192.168.229.1 -p tcp --sport 22 -m state --state ESTABLISHED,RELATED -j ACCEPT

echo "REGRAS TRAFEGO DNS"
$ipt -A INPUT -p udp --sport 53 -j LOG --log-prefix "DNS_IN: " --log-level info 
$ipt -A INPUT -i $iface -s 192.168.229.2 -p udp --sport 53 -m state --state ESTABLISHED,RELATED -j ACCEPT

$ipt -A OUTPUT -p udp --dport 53 -j LOG --log-prefix "DNS_OUT: " --log-level info
$ipt -A OUTPUT -o $iface -d 192.168.229.2 -p udp --dport 53 -j ACCEPT

echo "REGRAS TRAFEGO HTTPS/HTTP"
$ipt -A OUTPUT -p tcp --dport 80 -j LOG --log-prefix "HTTP: " --log-level info
$ipt -A OUTPUT -p tcp --dport 443 -j LOG --log-prefix "HTTPS: " --log-level info
$ipt -A OUTPUT -o $iface -m multiport -p tcp --dport 80,443 -j ACCEPT

echo "REGRAS/BLACKLIST PORT-SCAN - /proc/net/xt_recent/"

$ipt -A INPUT -f -i $iface -j LOG  --log-prefix "FRAGMENTS :" --log-level info

$ipt -A INPUT -p tcp --tcp-flags SYN,ACK SYN -i $iface -m recent --name blacklist --set -j LOG --log-prefix "SYN SCAN: " --log-level info
$ipt -A INPUT -p tcp --tcp-flags SYN,ACK SYN -i $iface -m recent --update --hitcount 1 --name blacklist --seconds 350 -m comment --comment "BLACKLIST SYN SCAN"
$ipt -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -i $iface -m recent  --name blacklist --set -m comment --comment "DROP/BLACKLIST SYN/ACK SCAN" -j LOG --log-prefix "SYN/ACK SCAN: " --log-level info

$ipt -A INPUT -p tcp --tcp-flags ALL NONE -i $iface -m recent --name blacklist --set -m comment --comment "DROP/BLACKLIST NULL SCAN" -j LOG --log-prefix "NULL SCAN: " --log-level info
$ipt -A INPUT -p tcp --tcp-flags ALL ALL -i $iface -m recent --name blacklist --set -m comment --comment "DROP/BLACKLIST XMAS FULL SCAN" -j LOG --log-prefix "XMAS FULL SCAN: " --log-level info
$ipt -A INPUT -p tcp --tcp-flags ACK ACK -i $iface -m recent --name blacklist --set -m comment --comment "DROP/BLACKLIST ACK SCAN" -j LOG --log-prefix "ACK SCAN: " --log-level info

$ipt -A INPUT -p tcp --tcp-flags ALL URG,PSH,FIN -i $iface -m recent --name blacklist --set -m comment --comment "DROP/BLACKLIST -ST SCAN" -j LOG --log-prefix "URG,PSH,FIN SCAN: " --log-level info
$ipt -A INPUT -p tcp --tcp-flags ALL FIN -i $iface -m recent --name blacklist --set -m comment --comment "DROP/BLACKLIST FIN SCAN" -j LOG --log-prefix "FIN SCAN: " --log-level info
$ipt -A INPUT -p tcp --tcp-flags ALL FIN,ACK -i $iface -m recent --name blacklist --set -m comment --comment "DROP/BLACKLIST FIN/ACK SCAN" -j LOG --log-prefix "FIN SCAN: " --log-level info
$ipt -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -i $iface -m recent --name blacklist --set -m comment --comment "DROP/XMAS TREE SCAN" -j LOG --log-prefix "XMAS TREE SCAN: " --log-level info

$ipt -A INPUT -p tcp --tcp-flags RST RST -i $iface -m recent --name blacklist --set -m comment --comment "DROP/RST SMURF SCAN" -j LOG --log-prefix "SMURF REJECT: " --log-level info

echo "MISC LOG"
$ipt -A INPUT ! -i lo -j LOG --log-prefix "DROP_IN LOG: " --log-ip-options --log-tcp-options --log-level info
$ipt -A OUTPUT ! -o lo -j LOG --log-prefix "DROP_OUT LOG: " --log-ip-options --log-tcp-options --log-level info




FIN,SYN,RST,PSH,ACK,URG NONE
FIN,SYN FIN,SYN
SYN,RST SYN,RST
SYN,FIN SYN,FIN
FIN,RST FIN,RST 
FIN,ACK FIN
ACK,URG URG
ACK,FIN FIN 
ACK,PSH PSH
ALL ALL
ALL NONE
ALL FIN,PSH,URG
ALL SYN,FIN,PSH,URG
ALL SYN,RST,ACK,FIN,URG

========

#$ipt -A INPUT -p tcp --tcp-flags ALL NONE -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix "NULL SCAN " --log-level info

$ipt -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -i $iface -j LOG --log-prefix "XMAS SCAN: " --log-level info
$ipt -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -i $iface -j DROP

$ipt -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -i $iface -j LOG --log-prefix "SYN/ACK SCAN: " --log-level info
$ipt -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -i $iface -j DROP 

$ipt -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -i $iface -j LOG --log-prefix "SYN/FIN SCAN: " --log-level info
$ipt -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -i $iface -j DROP

$ipt -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -i $iface -j LOG --log-prefix "SYN/RST SCAN: " --log-level info
$ipt -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -i $iface -j DROP

$ipt -A INPUT -p tcp --tcp-flags SYN,URG SYN,URG -i $iface -j LOG --log-prefix "SYN/URG SCAN: " --log-level info
$ipt -A INPUT -p tcp --tcp-flags SYN,URG SYN,URG -i $iface -j DROP

$ipt -A INPUT -p tcp --tcp-flags ALL FIN -i $iface -j LOG --log-prefix "FIN SCAN: " --log-level info
$ipt -A INPUT -p tcp --tcp-flags ALL FIN -i $iface -j DROP

$ipt -A INPUT -p tcp --tcp-flags ACK,RST RST -i $iface -j LOG --log-prefix "RST SCAN: " --log-level info
$ipt -A INPUT -p tcp --tcp-flags ACK,RST RST -i $iface -j DROP

$ipt -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -i $iface -j LOG --log-prefix "FIN/RST SCAN: " --log-level info
$ipt -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -i $iface -j DROP 

$ipt -A INPUT -p tcp --tcp-flags ACK ACK -i $iface -j LOG --log-prefix "ACK SCAN: " --log-level info
$ipt -A INPUT -p tcp --tcp-flags ACK ACK -i $iface -j DROP


vecho "REGRAS ANTI-SPOOF"
$IPTABLES -A INPUT -i $iface ! -s 192.168.229.0/24 -j LOG --log-prefix "IP SPOOF: "
$IPTABLES -A INPUT -i $iface ! -s 192.168.229.0/24 -j DROP


$ipt -A INPUT -p tcp --tcp-flags ACK,RST RST -i $iface -j LOG --log-prefix "ACK/RST SCAN: " --log-level info
$ipt -A INPUT -p tcp --tcp-flags ACK,RST RST -i $iface -j DROP

$ipt -A INPUT -p tcp --tcp-flags ACK,PSH PSH -i $iface -j LOG --log-prefix "ACK/PSH SCAN: " --log-level info
$ipt -A INPUT -p tcp --tcp-flags ACK,PSH PSH -i $iface -j DROP 



$ipt -A INPUT -p tcp --tcp-flags RST RST -i $iface -j LOG --log-prefix "RST :" --log-level info
$ipt -A INPUT -p tcp --tcp-flags RST RST -i $iface -j DROP





