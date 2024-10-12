#!/bin/sh

cd ..

./run_docker.sh poetry run gtd validate samples/custom/sample.c fib xtea interact
# Super operators
./run_docker.sh poetry run gtd validate -s samples/custom/sample.c fib xtea interact
