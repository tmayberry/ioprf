all:	main.pdf

main.pdf: *.tex *.bib *.aux *.blg *.bbl
	rubber -df main.tex
