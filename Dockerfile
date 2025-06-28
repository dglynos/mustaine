FROM debian:12

WORKDIR /app

COPY . /app

RUN apt-get update
RUN apt-get install -y build-essential gcc make libssl-dev libmagic-dev libcurl4-openssl-dev
RUN make clean
RUN make

