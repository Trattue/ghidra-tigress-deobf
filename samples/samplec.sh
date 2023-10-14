export TIGRESS_HOME=$(pwd)
./tigress --Environment=x86_64:Linux:Gcc:4.6 \
    --Transform=Virtualize \
    	--Functions=fib,xtea,interact \
    	--VirtualizeDispatch=ifnest \
    	--VirtualizeMaxMergeLength=5 --VirtualizeSuperOpsRatio=2.0 \
    --Transform=EncodeArithmetic \
        --Functions=fib,xtea,interact  \
    --out=samplec.out.c sample.c
gcc samplec.out.c -o samplec.out -gdwarf-4
