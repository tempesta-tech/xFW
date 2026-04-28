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

