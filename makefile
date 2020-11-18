all: idea.pdf rfid.pdf

idea.pdf: idea.tex
	rubber -d idea

rfid.pdf: rfid.tex
	rubber -d rfid
