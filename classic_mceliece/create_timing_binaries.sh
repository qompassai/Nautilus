#!/bin/bash

rm -rf timing_binaries_$1/

mkdir timing_binaries_$1
mkdir timing_binaries_$1/timing_arm/
mkdir timing_binaries_$1/timing_x86/
mkdir timing_binaries_$1/timing_arm/vec_$1/
mkdir timing_binaries_$1/timing_arm/no_vec_$1/
mkdir timing_binaries_$1/timing_x86/vec_$1/
mkdir timing_binaries_$1/timing_x86/no_vec_$1/

for opt_level in 0 1 2 3
do
	make kat ARCH=arm OPT=$opt_level VEC=y KAT=$1
	mv kat timing_binaries_$1/timing_arm/vec_$1/kat_O$opt_level

	make kat ARCH=arm OPT=$opt_level VEC=n KAT=$1
        mv kat timing_binaries_$1/timing_arm/no_vec_$1/kat_O$opt_level

	make kat OPT=$opt_level VEC=y KAT=$1
        mv kat timing_binaries_$1/timing_x86/vec_$1/kat_O$opt_level

        make kat OPT=$opt_level VEC=n KAT=$1
        mv kat timing_binaries_$1/timing_x86/no_vec_$1/kat_O$opt_level


done


