clean:
	rm -f a.out
	rm -f vgcore*
	rm -f valgrind*
	rm -f RSAES.hpp
	rm -f *~
	rm -f mini-gmp/*~

test:
	@(cat RSAES.hpp | grep "#include <gmp.h>") && (echo "RSAES: Linking against lgmp" && g++ -lgmp -O2 tests_and_examples.cpp && ./a.out) || (echo "RSAES: Using mini-gmp instead of linkning to lgmp" && g++ -O3 tests_and_examples.cpp && ./a.out)

debug:
	@(cat RSAES.hpp | grep "#include <gmp.h>") && (echo "RSAES Debug: Linking against lgmp" && g++ -lgmp -g -O2 tests_and_examples.cpp && valgrind ./a.out) || (echo "RSAES Debug: Using mini-gmp instead of linkning to lgmp" && g++ -O3 -g tests_and_examples.cpp && valgrind ./a.out)

init:
ifeq ($(lib),)
init: lib
endif

ifeq ($(lib),no)
init: nolib
endif

ifeq ($(lib),yes)
init: lib
endif

lib:
	@rm -f RSAES.hpp
	@echo "RSAES: using <gmp.h>"
	@(echo "#include <gmp.h>"; cat RSAES.hpp.proto) > RSAES.hpp

nolib:
	@rm -f RSAES.hpp
	@echo "RSAES: using mini-gmp"
	@(echo "#include \"mini-gmp/mini-gmp.c\""; cat RSAES.hpp.proto) > RSAES.hpp
