export TIGRESS_HOME=$(pwd)
./tigress --Environment=x86_64:Linux:Gcc:4.6 \
    --Transform=Virtualize \
    	--Functions=fib,xtea,interact \
    	--VirtualizeDispatch=ifnest \
    --out=samplea.out.c sample.c
gcc samplea.out.c -o samplea.out -gdwarf-4
