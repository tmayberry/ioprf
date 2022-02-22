all:	plot.tex main.pdf

plot.tex: plot.pl code/benchmarks/*
	gnuplot -e "        set format '$$%g$$' ;       set terminal epslatex standalone monochrome;        set output 'plot.tex'         " plot.pl
	rubber --jobname pre_plot -df plot.tex
	gs -o pre_plot2.pdf -dNoOutputFonts -sDEVICE=pdfwrite pre_plot.pdf
	pdf2ps pre_plot2.pdf pre_plot2.ps
	ps2eps -f pre_plot2.ps
	generatePDFfromEPS .
	mv pre_plot2.pdf plot.pdf

main.pdf: *.tex *.bib *.aux *.blg *.bbl *.pl
	rubber -df main.tex

clean:
	rm -f *.pdf *.aux *.log plot.tex *.bbl *.blg *.out *.rubbercache *.ps *.eps
