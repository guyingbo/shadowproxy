FROM python:3.8-slim

WORKDIR /app/ShadowProxy

ADD . .

RUN python setup.py install

RUN rm -rf /app/ShadowProxy

ENTRYPOINT ["/usr/local/bin/shadowproxy"]
