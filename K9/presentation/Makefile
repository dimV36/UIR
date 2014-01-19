.PHONY : all clean tex pdf view

all: tex pdf view

tex: LDAP.tex

pdf: LDAP.pdf

view: LDAP.pdf
	okular LDAP.pdf
#	evince LDAP.pdf


LDAP.tex: LDAP.txt Makefile
	wiki2beamer LDAP.txt > LDAP.tex
	
LDAP.pdf: LDAP.tex Makefile
	pdflatex LDAP.tex

clean:
	rm LDAP.aux LDAP.log LDAP.nav LDAP.out LDAP.snm LDAP.tex LDAP.toc
