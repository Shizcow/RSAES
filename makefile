edit:
	g++ -lgmpxx -lgmp -g RSA.cpp

clean:
	rm a.out

run:	edit
	./a.out

debug: edit
	valgrind --leak-check=full ./a.out	
