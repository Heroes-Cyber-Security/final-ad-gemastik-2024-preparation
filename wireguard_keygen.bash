#!/bin/bash

if [ "$#" -ne 5 ]; then
    echo "Usage: $0 <NetworkInterface> <Endpoint> <Port> <Teams> <ClientsPerTeam>"
    exit 1
fi

network_interface="$1"
endpoint="$2"
port="$3"
teams="$4"
clients_per_team="$5"

server_private_key=$(wg genkey)
server_public_key=$(echo "$server_private_key" | wg pubkey)

echo "[Interface]" > wg0.conf
echo "Address = 10.10.0.1/8" >> wg0.conf
echo "ListenPort = $port" >> wg0.conf
echo "PrivateKey = $server_private_key" >> wg0.conf
echo "" >> wg0.conf
echo "PostUp = iptables -I INPUT -p udp --dport $port -j ACCEPT" >> wg0.conf
echo "PostUp = iptables -I FORWARD -i wg0 -j ACCEPT" >> wg0.conf
echo "PostUp = iptables -t nat -I POSTROUTING -o $network_interface -j MASQUERADE" >> wg0.conf
echo "PostUp = iptables -t nat -I POSTROUTING -o cyber_network -j MASQUERADE" >> wg0.conf
echo "PostUp = iptables -I DOCKER-USER -i cyber_network -o forcad_network -j ACCEPT" >> wg0.conf
echo "PostUp = iptables -I DOCKER-USER -i forcad_network -o cyber_network -j ACCEPT" >> wg0.conf
echo "" >> wg0.conf
echo "PostDown = iptables -D INPUT -p udp --dport $port -j ACCEPT" >> wg0.conf
echo "PostDown = iptables -D FORWARD -i wg0 -j ACCEPT" >> wg0.conf
echo "PostDown = iptables -t nat -D POSTROUTING -o $network_interface -j MASQUERADE" >> wg0.conf
echo "PostDown = iptables -t nat -D POSTROUTING -o cyber_network -j MASQUERADE" >> wg0.conf
echo "PostDown = iptables -D DOCKER-USER -i cyber_network -o forcad_network -j ACCEPT" >> wg0.conf
echo "PostDown = iptables -D DOCKER-USER -i forcad_network -o cyber_network -j ACCEPT" >> wg0.conf
echo "" >> wg0.conf
echo "" >> wg0.conf
echo "" >> wg0.conf

for ((i=1; i<=$teams; i++)); do
    echo "### Team $i ###" >> wg0.conf
    
    for ((j=1; j<=$clients_per_team; j++)); do
        client_private_key=$(wg genkey)
        client_public_key=$(echo "$client_private_key" | wg pubkey)
        preshared_key=$(wg genpsk)
        
        echo "# Client $j #" >> wg0.conf
        echo "[Peer]" >> wg0.conf
        echo "PublicKey = $client_public_key" >> wg0.conf
        echo "PresharedKey = $preshared_key" >> wg0.conf
        echo "AllowedIPs = 10.80.$i.$j/32" >> wg0.conf
        echo "" >> wg0.conf
        
        client_conf="team${i}_client${j}.conf"
        echo "[Interface]" > $client_conf
        echo "PrivateKey = $client_private_key" >> $client_conf
        echo "Address = 10.80.$i.$j/32" >> $client_conf
        echo "" >> $client_conf
        echo "[Peer]" >> $client_conf
        echo "PublicKey = $server_public_key" >> $client_conf
        echo "PresharedKey = $preshared_key" >> $client_conf
        echo "Endpoint = $endpoint:$port" >> $client_conf
        echo "AllowedIPs = 10.0.0.0/8" >> $client_conf
        echo "PersistentKeepalive = 25" >> $client_conf
        echo "" >> $client_conf
    done
    
    echo "" >> wg0.conf
    echo "" >> wg0.conf
done
