export TIGRESS_HOME=$(pwd)
./tigress --Environment=x86_64:Linux:Gcc:4.6 --Seed=0 \
    --Transform=Virtualize \
    	--Functions=fib,xtea \
    	--VirtualizeDispatch=ifnest \
    --out=sample1.out.c sample.c
gcc sample1.out.c -o sample1.out -gdwarf-4
