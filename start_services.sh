#!/bin/bash

# Start Geth
nohup geth --http --http.addr 0.0.0.0 --http.port 8545 --http.corsdomain "*" --http.api eth,web3,personal,net &

# Wait for Geth to start
sleep 10

# Start Gunicorn with Uvicorn
/home/myuser/myquantumproject/new-env1/bin/gunicorn --pythonpath /home/myuser/myquantumproject myquantumproject.asgi:application -k uvicorn.workers.UvicornWorker -b 0.0.0.0:1010
