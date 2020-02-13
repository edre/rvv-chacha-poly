#!/bin/bash

# Dependencies to be installed and on the PATH:
# https://github.com/riscv/riscv-gnu-toolchain
# https://github.com/riscv/riscv-isa-sim
#   configure --prefix=$RISCV --with-varch=v512:e64:s128
# https://github.com/riscv/riscv-pk

ISA=rv64gcv

riscv64-unknown-elf-gcc -march=$ISA main.c boring.c vchacha.s vpoly.s -o main -O &&
    spike --isa=$ISA `which pk` main
