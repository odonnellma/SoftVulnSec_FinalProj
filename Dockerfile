FROM ubuntu:20.10

WORKDIR /tmp

ADD /src/main.py .
ADD /src/dos.py .

RUN apt update -y

# Installing text editors
RUN apt install vim -y
RUN apt install emacs -y
RUN apt install nano -y
RUN apt install less -y

#Installing networking tools
RUN apt install curl -y
RUN apt install net-tools -y
RUN apt install netcat -y

#Installing Python3
RUN apt install python3 -y

RUN apt install pip -y

# Installing pip
RUN pip install --upgrade pip && \
    pip install scapy && \
    pip install oyaml

ENTRYPOINT ["python3", "main.py"]
