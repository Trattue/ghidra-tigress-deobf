docker build --platform linux/amd64 -t ghidra-tigress-deobf .
docker run --platform linux/amd64 --rm -it -v $PWD:/gtd --name ghidra-tigress-deobf -i ghidra-tigress-deobf:latest "$@"
