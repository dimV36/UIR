.PHONY : all clean tex pdf view

cluster.txt: cluster.txt Makefile
	dot cluster.txt -ocluster.png -Tpng
	gwenview cluster.png