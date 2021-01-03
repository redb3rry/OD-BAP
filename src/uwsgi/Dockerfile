FROM python:3.7-alpine
WORKDIR /var/www
ENV FLASK_APP app/app.py
ENV FLASK_RUN_HOST 0.0.0.0
RUN apk add --no-cache gcc musl-dev linux-headers
COPY ./src/uwsgi/uwsgi.ini uwsgi.ini
COPY ./src/uwsgi/wsgi.py wsgi.py
COPY ./src/uwsgi/requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY ./src/uwsgi/app app
CMD ["uwsgi", "--ini", "uwsgi.ini"]
