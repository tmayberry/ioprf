#!/bin/bash

#Total time
grep RECEIVER $1 |awk '{print substr($22,2)}' >$1.data

#CPU
grep SENDER $1 |awk '{print substr($8,2)}' >$1.cpu.sender.data
grep RECEIVER $1 |awk '{print substr($8,2)}' >$1.cpu.receiver.data

#Data
grep SENDER $1 |awk '{print substr($34,2)}' >$1.comm.sender.data
grep RECEIVER $1 |awk '{print substr($34,2)}' >$1.comm.receiver.data
