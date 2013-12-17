.PHONY : all clean tex pdf view

cluster.txt: Makefile
	rm -f cluster.png
	dot cluster.txt -o../files/cluster.png -Tpng
	gwenview ../files/cluster.png

clean:
	rm -f ../files/cluster.png