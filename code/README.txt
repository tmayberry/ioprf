To compile this source code, you need to install the EMP-Tool library available at:
https://github.com/emp-toolkit/emp-tool

To compile the source code on Linux, just type "make".

On Mac, you need Homebrew with gcc/g++ 10. Apple's clang compiler is
not supported at this time. To compile on Mac, type "make
malicious-mac".

This gives you the "malicious" executable which you will run in
parallel once as the sender and once as the receiver (in a separate
terminal or using our "run" script introduced below). "malicious"
requires the following command line parameters.

1. Party number: use 1 for sender and 2 for receiver.

2. The TCP port number sender and receiver will use to communicate:
use, e.g., 12345.

3. The receiver's input string in a simple bit notation, e.g.,
"11001111" for an \ell=8 bit string. Note that the sender also has to
specify a bit string, but its exact value obviously does not have to
match the receiver's, only the lengths of the bit strings have to be
equal.

4. The number of runs you want to evaluate the iOPRF between sender
and receiver. For example, a value of 10 means that sender and
receiver evaluate the iOPRF on the sender's input string a total of 10
times.

You can also use the "run" script to start both instances of
"malicious" at the same time. The notation here is
"./run ./malicious STRING RUNS",
where STRING is the binary string, and runs the number of runs.

For details on how to set latency with Linux' "tc" command, please see
https://wiki.linuxfoundation.org/networking/netem
