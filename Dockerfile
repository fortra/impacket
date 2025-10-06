FROM python:3.13-alpine as compile
WORKDIR /opt
RUN apk add --no-cache git gcc musl-dev python3-dev libffi-dev openssl-dev cargo
RUN python3 -m pip install virtualenv
RUN virtualenv -p python venv
ENV PATH="/opt/venv/bin:$PATH"
RUN git clone --depth 1 https://github.com/fortra/impacket.git
RUN python3 -m pip install impacket/

FROM python:3.13-alpine
COPY --from=compile /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENTRYPOINT ["/bin/sh"]
