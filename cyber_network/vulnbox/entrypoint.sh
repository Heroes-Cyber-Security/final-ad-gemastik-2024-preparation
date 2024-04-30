iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination 10.80.150.1:53
iptables -I FORWARD -j ACCEPT
iptables -t nat -A POSTROUTING -j MASQUERADE

service ssh start

dockerd &

sleep 10

cd ./flags_shop
python3 app.py &

cd ../cyberuni
bash deploy.sh &

tail -f /dev/null
