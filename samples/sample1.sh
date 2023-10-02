export TIGRESS_HOME=$(pwd)
./tigress --Environment=x86_64:Linux:Gcc:4.6 \
    --Transform=Virtualize \
    	--Functions=fib,xtea,interact \
    	--VirtualizeDispatch=ifnest \
    --out=sample1.out.c sample.c
gcc sample1.out.c -o sample1.out -gdwarf-4
