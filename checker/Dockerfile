FROM python:3
RUN apt-get update

COPY requirements.txt .
RUN pip3 install -r requirements.txt

COPY . .
WORKDIR .

ENTRYPOINT [ "gunicorn", "-c", "gunicorn.conf.py", "checker:app" ]