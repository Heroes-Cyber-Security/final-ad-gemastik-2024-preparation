service ssh start

dockerd &

sleep 10

cd ./flags_shop
python3 app.py &

cd ../cyberuni
bash deploy.sh &

tail -f /dev/null
