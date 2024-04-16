docker build --platform linux/amd64 -t ghidra-tigress-deobf .
docker run --platform linux/amd64 --rm -it -v $PWD/plugins:/gtd/plugins --name ghidra-tigress-deobf -i ghidra-tigress-deobf:latest "$1"
