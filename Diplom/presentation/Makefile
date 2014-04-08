.PHONY : all clean tex pdf view

all: tex pdf view

tex: diplom.tex

pdf: diplom.pdf

view: diplom.pdf
	okular ../pdf/diplom.pdf
#	evince diplom.pdf


diplom.tex: diplom.txt Makefile
	wiki2beamer diplom.txt > diplom.tex
	
diplom.pdf: diplom.tex Makefile
	pdflatex diplom.tex 
	cp diplom.pdf ../pdf/diplom.pdf
	
clean:
	rm diplom.aux diplom.log diplom.nav diplom.out diplom.snm diplom.tex diplom.toc diplom.vrb diplom.pdf
