#!/bin/bash

# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License") ;
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Dependencies to be installed and on the PATH:
# https://github.com/riscv/riscv-gnu-toolchain
# I got qemu from my package manager.

riscv64-unknown-elf-gcc -march=rv64gcv_zvkb main.c boring.c vchacha.s vpoly.s -o main -O -static &&
    qemu-riscv64 -cpu rv64,v=true,vlen=512,zvkb=true main
