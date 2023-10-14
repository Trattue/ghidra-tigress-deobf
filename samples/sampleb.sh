export TIGRESS_HOME=$(pwd)
./tigress --Environment=x86_64:Linux:Gcc:4.6 \
    --Transform=Virtualize \
    	--Functions=fib,xtea,interact \
    	--VirtualizeDispatch=ifnest \
    	--VirtualizeMaxMergeLength=5 --VirtualizeSuperOpsRatio=2.0 \
    --out=sampleb.out.c sample.c
gcc sampleb.out.c -o sampleb.out -gdwarf-4
