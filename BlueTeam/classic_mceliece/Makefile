kat_kem.rsp: kat
	./run

kat: Makefile nist/kat_kem.c nist/rng.c nist/rng.h randombytes.h benes.c bm.c controlbits.c decrypt.c encrypt.c gf.c operations.c pk_gen.c root.c sk_gen.c synd.c transpose.c util.c    
ifeq ($(ARCH), arm)
	./build.aarch64 $(OPT) $(VEC) $(KAT)
else
	./build $(OPT) $(VEC) $(KAT)
endif

