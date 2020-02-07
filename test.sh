#!/bin/bash

# Dependencies to be installed and on the PATH:
# https://github.com/riscv/riscv-gnu-toolchain
# https://github.com/riscv/riscv-isa-sim
# https://github.com/riscv/riscv-pk

ISA=rv64gcv

riscv64-unknown-elf-as -march=$ISA vector.asm -o vector.o &&
    riscv64-unknown-elf-gcc main.c boring.c vector.o -o main &&
    spike --isa=$ISA `which pk` main