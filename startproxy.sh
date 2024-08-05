#!/bin/sh

trap 'kill 0' SIGINT
python -m http.server 8000 &
ssh -vND localhost:8001 localhost

