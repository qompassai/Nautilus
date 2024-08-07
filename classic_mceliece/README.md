This repository contains a hardware/software co-design acceleration of Classic McEliece Key Encapsulation Mechanism (CM KEM).
It is based on the 3rd Round submission of the CM KEM to the NIST Post-Quantum Standardization contest.
The hardware/software co-design code is located at the "mceliece-20201010/zcu102/" branches. The different branches are different implementations for the security levels implemented in CM KEM.

The baseline implementation for the different security levels can be found in the "mceliece-20201010/baseline/" branches. 
The "mceliece-20201010/vec/" branches contain the manually vectorized code across the 64-bits in a long long.
The rest of the CM KEM implementations that we did not use in our proposal for development or comparison purposes are not included in this repo, but can be found at https://classic.mceliece.org/nist.html.

The master branch contains the baseline\mceliece348864 (Level 1) software implementation. 
The baseline code is the C software implementation of CM KEM with the addition of custom time measurement functions for different parts of the application.
Baseline software implementations have been augmented with custom time measurement functions for different parts of the application.

To compile and run the CM KEM application you should use the build file provided.
Specific flags for compilation are ARCH=<arm, x86> (default is x86), OPT=<number> where you define the gcc optimization level, VEC=<y, n> where the user defines if the coade auto-vectorization feature of gcc will be used and KAT=<number> where the user defines how many consecutive Known Answer Tests (KATs) will be executed.
An example compilation looks like this "make kat OPT=3 VEC=y KAT=10" where we specify compilation of the CM KEM Known Answer Test KAT application for -O3 gcc optimization level with code-autovectorization included and for 10 consecutive KAT tests. 
After we can execute the binray "./kat" and see the timing measurements at the standard output.

Our code is tested in Ubuntu 18.04. The user needs to install the libssl-dev package for the compilation to succeed.

Code residing in "zcu102/" branches is our hardware/software co-design acceleration and is still subject to changes.

LIBRARIES NEEDED

KECCAK

For the compilation of the source code we need the Keccak library (libkeccak.a) and the SimpleFIPS202.h header file which is part of the Keccak library headers (libkeccak.a.headers).
For this reason we clone the Github repo of the [XKCP](https://github.com/XKCP/XKCP). For specific build targets check the README of the git repo. In our case, we performed the following steps
1. Follow the instructions in the XKCP repository and install all dependencies
2. Build the libXKCP libraries for the x86 architecture.
3. The crypto_hash.h and the build file from the Classic McEliece project need the <libkeccak.a.headers/SimpleFIPS202.h> header file and the libkeccak.a static library. Since the XKCP repo produces  <libXKCP.a.headers/SimpleFIPS202.h> header file and a libXKCP.a static library we renamed the Classic Mceliece files mentioned above to match the XKCP naming convention. 
4. We placed the <libXKCP.a.headers/SimpleFIPS202.h> header file and the libXKCP.a static library in the subroutines/ folder and the lib/ folder (we created the latter specifically for this reason). We also made sure to put the appropriate -L flag to the build file so that gcc can find the libXKCP.a library.

CRYPTO

For the crypto library we used the one provided by the Linux packaga manager (libcrypto.so.1.1).

