export TIGRESS_HOME=$(pwd)
./tigress --Environment=x86_64:Linux:Gcc:4.6 \
    --Transform=Virtualize \
    	--Functions=fib,xtea,interact \
    	--VirtualizeDispatch=ifnest \
    	--VirtualizeMaxMergeLength=5 --VirtualizeSuperOpsRatio=2.0 \
    --out=sample2.out.c sample.c
gcc sample2.out.c -o sample2.out -gdwarf-4
