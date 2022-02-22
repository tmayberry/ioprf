#!/usr/bin/python
import random
import string
import sys

if len(sys.argv)!=3:
    print("Arguments required: number of random lines server|client")
    exit(-1)
N = int(sys.argv[1])
myLength = 10
for i in range(N):
    a = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(myLength))
    b = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(myLength))
    if sys.argv[2]=="server":
        print (a+" "+b)
    else:
        print(a)
