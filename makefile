all: idea.pdf rfid.pdf ioprf-proof.pdf rfid-proof.pdf main.pdf


main.pdf: main.tex def.tex construction.tex macros.tex ioprf.tex
	rubber -d main

idea.pdf: idea.tex macros.tex def.tex
	rubber -d idea

rfid.pdf: rfid.tex macros.tex rf.tex
	rubber -d rfid

ioprf-proof.pdf: ioprf-proof.tex macros.tex ioprf.tex
	rubber -d ioprf-proof

rfid-proof.pdf: rfid-proof.tex macros.tex
	rubber -d rfid-proof
