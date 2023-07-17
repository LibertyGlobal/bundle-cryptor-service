#!/usr/bin/env bash
set -e
. /venv/bin/activate
echo "Starting Gunicorn with Flask application"
/venv/bin/gunicorn --bind 0.0.0.0:8081 app:app --daemon
echo "Gunicorn started"

echo "Starting Worker"
cd /usr/local/src
python3.8 ./service/worker.py
