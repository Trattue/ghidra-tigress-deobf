#!/bin/sh

./run_docker.sh gtd test samples/bkdrhash.c BKDRHash
./run_docker.sh gtd test samples/bphash.c BPHash
./run_docker.sh gtd test samples/dekhash.c DEKHash
./run_docker.sh gtd test samples/djbhash.c DJBHash
./run_docker.sh gtd test samples/elfhash.c ELFHash
./run_docker.sh gtd test samples/fnvhash.c FNVHash
./run_docker.sh gtd test samples/jshash.c JSHash
./run_docker.sh gtd test samples/pjwhash.c PJWHash
./run_docker.sh gtd test samples/rshash.c RSHash
./run_docker.sh gtd test samples/sdbmhash.c SDBMHash
# Super operators
./run_docker.sh gtd test -s samples/bkdrhash.c BKDRHash
./run_docker.sh gtd test -s samples/bphash.c BPHash
./run_docker.sh gtd test -s samples/dekhash.c DEKHash
./run_docker.sh gtd test -s samples/djbhash.c DJBHash
./run_docker.sh gtd test -s samples/elfhash.c ELFHash
./run_docker.sh gtd test -s samples/fnvhash.c FNVHash
./run_docker.sh gtd test -s samples/jshash.c JSHash
./run_docker.sh gtd test -s samples/pjwhash.c PJWHash
./run_docker.sh gtd test -s samples/rshash.c RSHash
./run_docker.sh gtd test -s samples/sdbmhash.c SDBMHash
