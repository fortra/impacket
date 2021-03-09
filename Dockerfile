FROM python:2-alpine as compile
WORKDIR /opt
RUN apk add --no-cache git gcc openssl-dev libffi-dev musl-dev
RUN pip install virtualenv
RUN virtualenv -p python venv
ENV PATH="/opt/venv/bin:$PATH"
RUN git clone --depth 1 https://github.com/SecureAuthCorp/impacket.git
RUN pip install impacket/

FROM python:2-alpine
COPY --from=compile /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENTRYPOINT ["/bin/sh"]