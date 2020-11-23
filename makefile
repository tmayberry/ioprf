all: idea.pdf rfid.pdf ioprf-proof.pdf rfid-proof.pdf

idea.pdf: idea.tex macros.tex
	rubber -d idea

rfid.pdf: rfid.tex macros.tex
	rubber -d rfid

ioprf-proof.pdf: ioprf-proof.tex macros.tex
	rubber -d ioprf-proof

rfid-proof.pdf: rfid-proof.tex macros.tex
	rubber -d rfid-proof
