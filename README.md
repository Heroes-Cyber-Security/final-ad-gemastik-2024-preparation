# Initial premise
ForcAD was not designed and created by me. I used the [ForcAD](https://github.com/pomo-mondreganto/ForcAD) made available by [pomo-mondreganto](https://github.com/pomo-mondreganto).
This repository has the sole purpose of speeding up the setup of ForcAD with services and checkers written by me and my team.

In this case the whole system is configured starting from a clean Ubuntu 22.04 and using the potential of docker for the network infrastructure.

<br/>

# Game Master

## Setup
```shell
wget https://raw.githubusercontent.com/DnyyGzd/ForcAD/main/setup.sh
bash setup.sh
```

## VPN Configuration
Install Wireguard with automated script.
```shell
wget https://raw.githubusercontent.com/angristan/wireguard-install/master/wireguard-install.sh
sudo bash wireguard-install.sh
```
* Server Wireguard IPv4: 10.10.0.1
* Allowed IPs list: 10.0.0.0/8

Create every client configuration file you want.

Add these lines in `/etc/wireguard/wg0.conf`
* `PostUp = iptables -t nat -I POSTROUTING -o cyber_network -j MASQUERADE`
* `PostUp = iptables -I DOCKER-USER -i cyber_network -o forcad_network -j ACCEPT`
* `PostUp = iptables -I DOCKER-USER -i forcad_network -o cyber_network -j ACCEPT`

Restart VPN
```shell
wg-quick down wg0
wg-quick up wg0
```

## ForcAD Configuration
* Open `config.yml` file
  * Change admin `username` and `password`
  * Delete or add teams
    * Range 10.80.1.1 - 10.80.250.1
  * Change `timezone` and `start_time` (optional)

<br/>

# Team Clients
Get a client configuration file from the Game Master.
```shell
sudo apt install wireguard resolvconf
```
Move to your configuration file place.
```shell
sudo mv <conf_file>.conf /etc/wireguard/<conf_file>.conf
wg-quick up <conf_file>
```

<br/>

# Info
* Start the ForcAD competition
  * Run `./control.py setup && ./control.py start`
* Print team tokens and send to each team correspondingly
  * Run `./control.py print_tokens`
* Stop the ForcAD competition
  * Run `./control.py reset`
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
