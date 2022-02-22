#!/usr/bin/python
import sys, os, time

def genString(ell):
    x = ""
    for i in xrange(ell):
        x = x + str(i%2)
    return x

if len(sys.argv)!=4:
    print sys.argv[0]+" ELL ROUNDS OUTPUTFILE"
    exit(1)

f = open(sys.argv[3], "w+") 
for i in range(1,int(sys.argv[1])+1,1):
    print "ELL="+str(i),
    cmd = "./run ./malicious "+genString(i)+" "+sys.argv[2]
    stream = os.popen(cmd)
    lines = stream.read()
    time.sleep(1)
    f.write(lines + "\n")
    print(lines)
    f.flush()
    sys.stdout.flush()

f.close()
