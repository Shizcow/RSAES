default:
	@echo "RSAES: Check the README for makefile instructions"

clean:
	rm -f a.out
	rm -f vgcore*
	rm -f impl.hpp
	rm -f *~
	rm -f mini-gmp/*~
	rm -f \#*\#
	rm -f mini-gmp/\#*\#


test:
	$(eval CXX := $(if $(CXX),$(CXX),"g++"))
	$(eval GMP_H := $(if $(shell grep "include <gmp.h>" impl.hpp),-lgmp,))

	$(CXX) $(GMP_H) $(CXXFLAGS) -lcrypto tests_and_examples.cpp -Wall -O2 && ./a.out

debug:
	$(eval CXX := $(if $(CXX),$(CXX),"g++"))
	$(eval GMP_H := $(if $(shell grep "include <gmp.h>" impl.hpp),-lgmp,))

	$(CXX) $(GMP_H) $(CXXFLAGS) -lcrypto -g tests_and_examples.cpp && valgrind --track-origins=yes --leak-check=full ./a.out

time:
	$(eval CXX := $(if $(CXX),$(CXX),"g++"))
	$(eval GMP_H := $(if $(shell grep "include <gmp.h>" impl.hpp),-lgmp,))

	$(CXX) $(GMP_H) $(CXXFLAGS) -lcrypto -O2 tests_and_examples.cpp && time ./a.out





init:
	$(eval lib := $(if $(lib),$(lib),yes))
	$(eval msg := $(if $(filter $(lib),yes),"RSAES: using <gmp.h>"))
	$(eval msg := $(if $(filter $(lib),no),"RSAES: using mini-gmp",$(msg)))
	$(eval searchstr := $(if $(filter $(lib),yes),"\\\#include <gmp.h>"))
	$(eval searchstr := $(if $(filter $(lib),no),"\#include \"mini-gmp/mini-gmp.c\"",$(searchstr)))

	@rm -f impl.hpp
	@echo $(msg)
	@(echo $(searchstr); cat impl-proto.hpp) > impl.hpp
