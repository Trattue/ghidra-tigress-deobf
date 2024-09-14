#!/bin/sh

cd ..

./run_docker.sh gtd validate samples/simple_hash/bkdrhash.c BKDRHash
./run_docker.sh gtd validate samples/simple_hash/bphash.c BPHash
./run_docker.sh gtd validate samples/simple_hash/dekhash.c DEKHash
./run_docker.sh gtd validate samples/simple_hash/djbhash.c DJBHash
./run_docker.sh gtd validate samples/simple_hash/elfhash.c ELFHash
./run_docker.sh gtd validate samples/simple_hash/fnvhash.c FNVHash
./run_docker.sh gtd validate samples/simple_hash/jshash.c JSHash
./run_docker.sh gtd validate samples/simple_hash/pjwhash.c PJWHash
./run_docker.sh gtd validate samples/simple_hash/rshash.c RSHash
./run_docker.sh gtd validate samples/simple_hash/sdbmhash.c SDBMHash
# Super operators
./run_docker.sh gtd validate -s samples/simple_hash/bkdrhash.c BKDRHash
./run_docker.sh gtd validate -s samples/simple_hash/bphash.c BPHash
./run_docker.sh gtd validate -s samples/simple_hash/dekhash.c DEKHash
./run_docker.sh gtd validate -s samples/simple_hash/djbhash.c DJBHash
./run_docker.sh gtd validate -s samples/simple_hash/elfhash.c ELFHash
./run_docker.sh gtd validate -s samples/simple_hash/fnvhash.c FNVHash
./run_docker.sh gtd validate -s samples/simple_hash/jshash.c JSHash
./run_docker.sh gtd validate -s samples/simple_hash/pjwhash.c PJWHash
./run_docker.sh gtd validate -s samples/simple_hash/rshash.c RSHash
./run_docker.sh gtd validate -s samples/simple_hash/sdbmhash.c SDBMHash
