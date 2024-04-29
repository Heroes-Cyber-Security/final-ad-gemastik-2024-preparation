FROM ubuntu:20.04

ENV MasterKey="AuthenticationSystemMasterKey000" \
    ExamNotesKey="ExamNotesAppDefaultKey0000000000" \
    EncryptedNotesKey="EncryptedNotesAppDefaultKey00000" \
    ExamPortalKey="ExamPortalAppDefaultKey000000000"

WORKDIR /service/server

ADD authlib.cpython-38-x86_64-linux-gnu.so server.py user_handlers.py .

RUN apt update && \
    apt install -y python3 python3-dev socat python3-pip gcc g++ make libffi-dev && \
    useradd --no-create-home --shell /bin/false --uid 1000 --user-group srv && \
    mkdir users && \
    chmod +x server.py && \
    chmod -R 777 users

USER srv

ENTRYPOINT socat -d TCP-LISTEN:8000,reuseaddr,fork EXEC:'timeout -k 5 30 python3 -u server.py'
