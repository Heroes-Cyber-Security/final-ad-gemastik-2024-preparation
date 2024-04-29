FROM ubuntu:20.04

ENV ExamNotesKey="ExamNotesAppDefaultKey0000000000"

WORKDIR /service/server

ADD app .

RUN apt update && \
    apt install -y python3 python3-dev socat python3-pip gcc g++ make libffi-dev && \
    pip3 install -r requirements.txt && \
    useradd --no-create-home --shell /bin/false --uid 1000 --user-group app1 && \
    mkdir data && \
    chmod +x server.py && \
    chmod -R 777 data

USER app1

ENTRYPOINT socat -d TCP-LISTEN:8000,reuseaddr,fork EXEC:'timeout -k 5 30 python3 -u server.py'
