FROM ubuntu:22.04

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y docker.io docker-compose-v2 openssh-server

RUN apt-get install -y bsdmainutils curl inetutils-ping iproute2 iptables mysql-client nano net-tools python3 python3-pip traceroute

RUN echo 'root:root' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

WORKDIR /usr/src/app

COPY . .

EXPOSE 22
EXPOSE 1234 1235 1236 1237

CMD [ "bash", "entrypoint.sh" ]

