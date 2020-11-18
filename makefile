all: idea.pdf rfid.pdf proof.pdf

idea.pdf: idea.tex
	rubber -d idea

rfid.pdf: rfid.tex
	rubber -d rfid

proof.pdf: proof.tex
	rubber -d proof
