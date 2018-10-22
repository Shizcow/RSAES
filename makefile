edit:
	g++ -lgmpxx -lgmp -O3 -Wall -Werror -std=c++17 RSA.cpp

clean:
	rm -f a.out
	rm -f vgcore*
	rm -f valgrind*

run:	edit
	./a.out

debug:
	g++ -lgmpxx -lgmp -O3 -g -std=c++17 RSA.cpp
	valgrind --leak-check=full ./a.out	
