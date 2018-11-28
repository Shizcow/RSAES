default:
	@echo "RSAES: Check the README for makefile instructions"

clean:
	rm -f a.out
	rm -f vgcore*
	rm -f RSAES.hpp
	rm -f *~
	rm -f mini-gmp/*~
	rm -f \#*\#
	rm -f mini-gmp/\#*\#

test:
ifeq ($(CXX),)
	@if (cat RSAES.hpp | grep "#include <gmp.h>") ; then (echo "RSAES: Linking against lgmp" && g++ -lgmp $(CXXFLAGS) tests_and_examples.cpp && ./a.out) ; else (echo "RSAES: Using mini-gmp" && g++ $(CXXFLAGS) tests_and_examples.cpp && ./a.out) ; fi
else
	@if (cat RSAES.hpp | grep "#include <gmp.h>") ; then (echo "RSAES: Linking against lgmp" && $(CXX) -lgmp $(CXXFLAGS) tests_and_examples.cpp && ./a.out) ; else (echo "RSAES: Using mini-gmp" && $(CXX) $(CXXFLAGS) tests_and_examples.cpp && ./a.out) ; fi
endif

debug:
ifeq ($(CXX),)
	@if (cat RSAES.hpp | grep "#include <gmp.h>") ; then (echo "RSAES: Linking against lgmp" && g++ -lgmp $(CXXFLAGS) tests_and_examples.cpp && ./a.out) ; else (echo "RSAES: Using mini-gmp" && g++ $(CXXFLAGS) tests_and_examples.cpp && valgrind ./a.out) ; fi
else
	@if (cat RSAES.hpp | grep "#include <gmp.h>") ; then (echo "RSAES: Linking against lgmp" && $(CXX) -lgmp $(CXXFLAGS) tests_and_examples.cpp && ./a.out) ; else (echo "RSAES: Using mini-gmp" && $(CXX) $(CXXFLAGS) tests_and_examples.cpp && valgrind ./a.out) ; fi
endif

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
	@(echo "#include <gmp.h>"; cat RSAES-proto.hpp) > RSAES.hpp

nolib:
	@rm -f RSAES.hpp
	@echo "RSAES: using mini-gmp"
	@(echo "#include \"mini-gmp/mini-gmp.c\""; cat RSAES-proto.hpp) > RSAES.hpp
