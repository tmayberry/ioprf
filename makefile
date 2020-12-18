all:	main.pdf

main.pdf: *.tex *.bib
	rubber -df main.tex
