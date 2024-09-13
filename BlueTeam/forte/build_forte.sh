#!/bin/bash

# Set compiler to GCC
export CC=gcc
export CXX=g++

# Set necessary compiler and linker flags
export CFLAGS="-march=native -O2"
export CXXFLAGS="$CFLAGS"
export LDFLAGS="-L/opt/libtorch/lib"

# Set libtorch paths
export TORCH_LIB_DIR=/opt/libtorch/lib
export TORCH_INCLUDE_DIR=/opt/libtorch/include

# Set CUDA environment variables
export CUDA_PATH=/opt/cuda
export CUDA_ROOT=/opt/cuda
export CUDA_TOOLKIT_ROOT_DIR=/opt/cuda

# Build the project
cargo clean
cargo build --release

