FROM python:3.6-alpine

RUN apk update && apk upgrade && \
    apk add gcc python3-dev musl-dev libffi-dev openssl-dev

WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app
RUN pip install -r requirements.txt --index-url https://artifacts.factioninc.com/repository/pypi-group/simple/
RUN pip install gunicorn

COPY . /usr/src/app

ARG RABBIT_HOST

ENV RABBIT_HOST ${RABBIT_HOST}

ENV PYTHONPATH=.:$PYTHONPATH
CMD ["gunicorn", "wsgi", "-b 0.0.0.0:8080"]
