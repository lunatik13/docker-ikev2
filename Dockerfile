FROM ubuntu:16.04

RUN set -ex \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y install strongswan strongswan-plugin-eap-mschapv2 strongswan-plugin-openssl moreutils iptables-persistent \
    && rm -rf /var/lib/apt/lists/* # cache busted 20160406.1

RUN rm /etc/ipsec.secrets

ADD ./etc/* /etc/
ADD ./bin/* /usr/bin/

# ROUTES SET UP
# RUN ufw disable
# RUN iptables -P INPUT ACCEPT
# RUN iptables -P FORWARD ACCEPT
# RUN iptables -F
# RUN iptables -Z
# RUN iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# RUN iptables -A INPUT -i lo -j ACCEPT
# RUN iptables -A INPUT -p udp --dport  500 -j ACCEPT
# RUN iptables -A INPUT -p udp --dport 4500 -j ACCEPT

# RUN iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s 10.10.10.0/24 -j ACCEPT
# RUN iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d 10.10.10.0/24 -j ACCEPT
# RUN iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -m policy --pol ipsec --dir out -j ACCEPT
# RUN iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE
# RUN iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s 10.10.10.0/24 -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360

# RUN netfilter-persistent save
# RUN netfilter-persistent reload

# RUN ipsec reload

EXPOSE 500/udp 4500/udp

CMD /usr/bin/start-vpn
