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
Run `bash wireguard_keygen.bash` to generate the server and team configuration files.

For example, if your server uses network interface `enp0s3`, ip `192.168.1.100`, port `51820` and you need `20` teams with `5` clients per team:
* `bash wireguard_keygen.bash enp0s3 192.168.1.100 51820 20 5`

## ForcAD Configuration
* Open `config.yml` file
  * Change admin `username` and `password`
  * Delete or add teams
    * `10.80.<team>.1`  -  1 <= team <= 255
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
sudo wg-quick up <conf_file>
```

<br/>

# Info
* Start the ForcAD competition
  * `./control.py setup && ./control.py start`
* Print team tokens and send to each team correspondingly
  * `./control.py print_tokens`
* Stop the ForcAD competition
  * `./control.py reset && sudo rm -rf docker_volumes`
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
