all:	main.pdf

main.pdf: *.tex
	rubber -df main.tex
