FROM nimlang/nim:2.0.0-regular

WORKDIR /usr/src/app

COPY . .

RUN nim install && nim build


ENTRYPOINT  ["dist/RTT"]
