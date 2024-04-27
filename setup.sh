sudo apt update && sudo apt full-upgrade -y

sudo apt install -y curl git python3-pip
sudo apt install -y docker.io docker-compose-v2

sudo usermod -aG docker $USER
newgrp docker

git clone https://github.com/DnyyGzd/ForcAD

pip3 install -r ForcAD/cli/requirements.txt
chmod +x ForcAD/control.py
