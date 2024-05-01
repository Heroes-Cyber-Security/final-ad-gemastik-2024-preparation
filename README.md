# Initial premise
ForcAD was not designed and created by me. I used the [ForcAD](https://github.com/pomo-mondreganto/ForcAD) made available by [pomo-mondreganto](https://github.com/pomo-mondreganto).
This repository has the sole purpose of speeding up the setup of ForcAD with services and checkers written by me and my team.

In this case the whole system is configured starting from a clean Ubuntu 22.04 and using the potential of docker for the network infrastructure.

<br/>

# Game Master

## Setup
From a clean Ubuntu 22.04:
* Update, upgrade and install necessary packets
* Install docker and docker compose v2
* Clone this repository
* Install ForcAD requirements
* Give execution permissions to control.py and checkers

There is an automatic script in this repository.
You can run in this way:
```shell
wget https://raw.githubusercontent.com/DnyyGzd/ForcAD/main/setup.bash
bash setup.bash
```

## ForcAD Configuration
* Open `config.yml` file
  * Change admin `username` and `password`
  * Delete or add teams
    * `10.80.<team>.1`
      * $1 \leq team \leq 255$
  * Change `timezone` and `start_time` (optional)

## VPN Configuration
Install Wireguard.
```shell
sudo apt install wireguard resolvconf
```

Run `wireguard_keygen.bash` to generate the server and team configuration files.

For example, if your server uses network interface `enp0s3`, ip `192.168.1.100`, port `51820` and you need `20` teams with `5` clients per team:
```shell
bash wireguard_keygen.bash enp0s3 192.168.1.100 51820 20 5
```

Move wg0.conf to wireguard directory.
```shell
sudo mv wg0.conf /etc/wireguard/wg0.conf
```

Start server wireguard.
```shell
sudo wg-quick up wg0
```

Share to team clients configuration files.

<br/>

# Team Clients
Install Wireguard.
```shell
sudo apt install wireguard resolvconf
```
Get a client configuration file from the Game Master and move to your configuration file place.
```shell
sudo mv <conf_file>.conf /etc/wireguard/<conf_file>.conf
```

Start client wireguard.
```shell
sudo wg-quick up <conf_file>
```

<br/>

# Run ForcAD
* Start vulnboxes from ForcAD/cyber_network directory
  * `docker compose up --build -d && docker compose logs -f`
* As soon as the vulnboxes are ready, start ForcAD from ForcAD directory
  * `./control.py setup && ./control.py start`
* Print team tokens and send to each team correspondingly
  * `./control.py print_tokens`
* When you want to stop ForcAD
  * `./control.py reset && sudo rm -rf docker_volumes`

<br/>

# Info
* Scoreboard
  * `http://10.10.0.1`
* Admin panel
  * `http://10.10.0.1/admin`
* Flag ids
  * `http://10.10.0.1/api/client/attack_data`
* Submit flags
  * `http://10.10.0.1/flags`
* Flag format
  * `[A-Z0-9]{31}=`

<br/>

# Code to submit flags
```python
#!/usr/bin/python3

import requests

def submit_flags(team_token, flags):
	print(requests.put(f'http://10.10.0.1/flags', headers={'X-Team-Token': team_token}, json=flags).text)
```
Please note: `flags` must be a list.
