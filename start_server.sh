#!/bin/bash

# Run the initialization script
/home/myuser/myquantumproject/new-env1/bin/python3.9 /home/myuser/myquantumproject/quantumapp/initialize_app.py

# Start the Gunicorn server
exec /home/myuser/myquantumproject/new-env1/bin/gunicorn --pythonpath /home/myuser/myquantumproject myquantumproject.asgi:application -k uvicorn.workers.UvicornWorker -b 0.0.0.0:1010
