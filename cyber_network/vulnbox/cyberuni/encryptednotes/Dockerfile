FROM ubuntu:20.04

ENV EncryptedNotesKey="EncryptedNotesAppDefaultKey00000"

WORKDIR /service/server

ADD app .

RUN apt-get update && \
    apt-get install -y python3 python3-dev socat python3-pip && \
    pip install -r requirements.txt && \
    mkdir -p /service/server/data && \
    chown -R nobody /service/server
    
USER nobody

ENTRYPOINT socat -d TCP-LISTEN:8000,reuseaddr,fork EXEC:'python3 server.py'
