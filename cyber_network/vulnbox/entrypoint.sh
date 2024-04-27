service ssh start

dockerd &

sleep 10

cd CyberUni
bash deploy.sh &

tail -f /dev/null

