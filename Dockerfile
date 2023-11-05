FROM nimlang/nim:2.0.0-regular

WORKDIR /usr/src/app

COPY . .

RUN nim install
RUN nim build

ARG RunMode
ENV RunMode=${RunMode}


# ENTRYPOINT  ["dist/RTT"]
# CMD ["dist/RTT","${RunMode}"]