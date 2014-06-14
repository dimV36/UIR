.PHONY : all clean tex pdf view

all: tex pdf view

tex: presentation.tex

pdf: presentation.pdf

view: presentation.pdf
#	okular ../pdf/presentation.pdf

presentation.tex: presentation.txt Makefile
	wiki2beamer presentation.txt > presentation.tex
	
presentation.pdf: presentation.tex Makefile
	pdflatex presentation.tex 
	cp presentation.pdf ../pdf/presentation.pdf
	
clean:
	rm presentation.aux presentation.log presentation.nav presentation.out presentation.snm presentation.tex presentation.toc presentation.pdf
