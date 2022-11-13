#syntax=docker/dockerfile:1.2

FROM    alpine:3.16.1 as base

RUN     apk update && \
        apk add gcc \
                memcached \
                musl-dev \
                py3-pip \
                git

COPY    requirements.txt requirements.txt

RUN     python3 -m pip install -r requirements.txt --no-cache-dir && \
        py4web setup --yes apps && \
        # Find all folders not named default in the ./apps folder update to one folder deep and remove them all.
        find ./apps -type d ! -name '__*' ! -name '.*' -maxdepth 1 -mindepth 1 -exec rm -rf "{}" \;

COPY    . ./apps/_default

EXPOSE  8000

WORKDIR /

# Development image.
FROM    base as development
COPY    requirements.development.txt requirements.development.txt 
RUN     python3 -m pip install -r requirements.development.txt --no-cache-dir
EXPOSE  5678
CMD     python3 ./apps/_default/py4web.development.py run apps --port=8000 --host=0.0.0.0 --password_file password.txt \
         --server rocketServer 

# Testing image.
FROM    base as testing
COPY    requirements.testing.txt requirements.testing.txt
COPY    requirements.development.txt requirements.development.txt
RUN     python3 -m pip install -r requirements.testing.txt --no-cache-dir
RUN     python3 -m pip install -r requirements.development.txt --no-cache-dir
EXPOSE  5678
CMD     python3 ./apps/_default/py4web.testing.py

# Production image.
FROM    base as production
CMD     py4web run apps --port=8000 --host=0.0.0.0 --password_file password.txt --server rocketServer --watch off --dashboard_mode none