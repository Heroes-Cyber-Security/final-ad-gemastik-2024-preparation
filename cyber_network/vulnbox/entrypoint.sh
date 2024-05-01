iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination 10.80.150.1:53     # Unipa ready
iptables -I FORWARD -j ACCEPT                                                               # Unipa ready
iptables -t nat -A POSTROUTING -j MASQUERADE                                                # Unipa ready

service ssh start

dockerd &

sleep 10

cd ./flags_shop
python3 app.py &

cd ../cyberuni
bash deploy.sh &

tail -f /dev/null
