reset
set ylabel "Time $(s)$"  offset 2,0,0 font "" textcolor lt -1 rotate

#set terminal qt
set key at 32,0.2
    set grid
    set logscale y
    set xrange [0:33]
    #set xtics (5,10,15,20,25,30)
    set xlabel "$\\ell$" 
    set yrange [0.01:100]
    #set ytics (0.01,0.1,1,10,100)
    plot "code/benchmarks/rtt-0ms.data" using (1+$0):($1/1000) w p ls 1 pt 1 t  "CPU ($0ms$ RTT)",\
    "code/benchmarks/rtt-0.5ms.data" using (1+$0):($1/1000) w p ls 1 pt 3 t  "LAN1 ($0.5ms$ RTT)",\
    "code/benchmarks/rtt-2ms.data" using (1+$0):($1/1000) w p ls 1 pt 4 t  "LAN2 ($2ms$ RTT)",\
    "code/benchmarks/rtt-30ms.data" using (1+$0):($1/1000) w p ls 1 pt 5  t  "WAN1 ($30ms$ RTT)",\
    "code/benchmarks/rtt-70ms.data" using (1+$0):($1/1000) w p ls 1 pt 6  t  "WAN2 ($70ms$ RTT)"
    
    #pause -1
