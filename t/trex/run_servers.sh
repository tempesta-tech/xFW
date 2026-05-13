#!/usr/bin/env bash

# Add routes to the generator server for ICMP echo and SYN-ACK
ip route replace 16.2.0.0/16 via 192.168.2.2 dev enp202s0f0np0
ip route replace 16.3.0.0/16 via 192.168.3.2 dev enp202s0f1np1

for i in $(seq 10 59); do
    sudo ip addr add 192.168.2.$i/24 dev enp202s0f0np0
    sudo ip addr add 192.168.3.$i/24 dev enp202s0f1np1
done
sleep 1

python3 -m http.server 8080 -b 192.168.2.1 &
python3 -m http.server 8080 -b 192.168.3.1 &
 for i in $(seq 10 59); do
	python3 -m http.server 8080 -b 192.168.2.$i &
	python3 -m http.server 8080 -b 192.168.3.$i &
done

