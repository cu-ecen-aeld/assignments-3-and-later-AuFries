#!/bin/bash

HOST="localhost"
PORT=9000
CLIENTS=5

for i in $(seq 1 $CLIENTS); do
(
    echo "Client $i: message"
) | nc -q 0 $HOST $PORT &
done

wait
echo "All clients finished."