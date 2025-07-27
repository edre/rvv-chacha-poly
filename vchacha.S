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

.global cycle_counter
.global instruction_counter
.global vector_chacha20
.global vector_chacha20_zvkb
.global vlmax_u32

vlmax_u32:
	vsetvli a0, x0, e32, m1, ta, ma
	ret


.macro vrotl_native a, r
vror.vi \a, \a, 32-\r
.endm

.macro vrotl_emulated a, r
vsll.vi v16, \a, \r
vsrl.vi v17, \a, 32-\r
vor.vv \a, v16, v17
.endm

.macro batch_add x0 x1 x2 x3 y0 y1 y2 y3
	vadd.vv \x0, \x0, \y0
	vadd.vv \x1, \x1, \y1
	vadd.vv \x2, \x2, \y2
	vadd.vv \x3, \x3, \y3
.endm

.macro batch_xor x0 x1 x2 x3 y0 y1 y2 y3
	vxor.vv \x0, \x0, \y0
	vxor.vv \x1, \x1, \y1
	vxor.vv \x2, \x2, \y2
	vxor.vv \x3, \x3, \y3
.endm

.macro batch_rotl name x0 x1 x2 x3 n
	vrotl_\name \x0 \n
	vrotl_\name \x1 \n
	vrotl_\name \x2 \n
	vrotl_\name \x3 \n
.endm

# Do the 4 quarter rounds interleaved to allow more instruction level parallelism.
.macro round name a0 a1 a2 a3 b0 b1 b2 b3 c0 c1 c2 c3 d0 d1 d2 d3
	# a += b; d ^= a; d <<<= 16;
	batch_add \a0, \a1, \a2, \a3, \b0, \b1, \b2, \b3
	batch_xor \d0, \d1, \d2, \d3, \a0, \a1, \a2, \a3
	batch_rotl \name, \d0, \d1, \d2, \d3, 16
	# c += d; b ^= c; b <<<= 12;
	batch_add \c0, \c1, \c2, \c3, \d0, \d1, \d2, \d3
	batch_xor \b0, \b1, \b2, \b3, \c0, \c1, \c2, \c3
	batch_rotl \name, \b0, \b1, \b2, \b3, 12
	# a += b; d ^= a; d <<<= 8;
	batch_add \a0, \a1, \a2, \a3, \b0, \b1, \b2, \b3
	batch_xor \d0, \d1, \d2, \d3, \a0, \a1, \a2, \a3
	batch_rotl \name, \d0, \d1, \d2, \d3, 8
	# c += d; b ^= c; b <<<= 7;
	batch_add \c0, \c1, \c2, \c3, \d0, \d1, \d2, \d3
	batch_xor \b0, \b1, \b2, \b3, \c0, \c1, \c2, \c3
	batch_rotl \name, \b0, \b1, \b2, \b3, 7
.endm

# Cell-based implementation strategy:
# v0-v15: Cell vectors. Each element is from a different block

## Function initialization
# Using the same order as the boring chacha arguments:
# a0 = uint8_t *out
# a1 = uint8_t *in
# a2 = size_t in_len
# a3 = uint8_t key[32]
# a4 = uint8_t nonce[12]
# a5 = uint32_t counter
.macro CHACHA_FUNC_BODY name
	# a2 = initial length in bytes
	# t3 = remaining 64-byte blocks to mix
	# t4 = remaining full blocks to read/write
	#  (if t3 and t4 are different by one, there is a partial block to manually xor)
	# t2 = vl in 64-byte blocks
	srli t4, a2, 6
	addi t3, a2, 63
	srli t3, t3, 6

	# Save enough registers to only load key and nonce once.
	sd s0, -8(sp)
	sd s1, -16(sp)
	sd s2, -24(sp)
	sd s3, -32(sp)
	sd s4, -40(sp)
	sd s5, -48(sp)
	sd s6, -56(sp)
	sd s7, -64(sp)
	sd s8, -72(sp)
	sd s9, -80(sp)
	sd s10, -88(sp)
	addi sp, sp, -96
	# Load key into registers.
	lw s0, 0(a3)
	lw s1, 4(a3)
	lw s2, 8(a3)
	lw s3, 12(a3)
	lw s4, 16(a3)
	lw s5, 20(a3)
	lw s6, 24(a3)
	lw s7, 28(a3)
	# Load nonce into registers.
	lw s8, 0(a4) 
	lw s9, 4(a4) 
	lw s10, 8(a4) 
	# Load constant into registers.
	li a3, 0x61707865 # "expa" little endian
	li a4, 0x3320646e # "nd 3" little endian
	li a6, 0x79622d32 # "2-by" little endian
	li a7, 0x6b206574 # "te k" little endian

encrypt_blocks_\name:
	# initialize vector state
	vsetvli t2, t3, e32, m1, ta, ma
	# Load 128 bit constant
	vmv.v.x v0, a3
	vmv.v.x v1, a4
	vmv.v.x v2, a6
	vmv.v.x v3, a7
	# Load key
	vmv.v.x v4, s0
	vmv.v.x v5, s1
	vmv.v.x v6, s2
	vmv.v.x v7, s3
	vmv.v.x v8, s4
	vmv.v.x v9, s5
	vmv.v.x v10, s6
	vmv.v.x v11, s7
	# Load counter, and increment for each element
	vid.v v12
	vadd.vx v12, v12, a5
	# Load nonce
	vmv.v.x v13, s8
	vmv.v.x v14, s9
	vmv.v.x v15, s10

	# Do 20 rounds of mixing.
	li t0, 20
round_loop_\name:
	# Mix columns
	round \name, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15
	# Mix diagonals
	round \name, v0, v1, v2, v3, v5, v6, v7, v4, v10, v11, v8, v9, v15, v12, v13, v14

	addi t0, t0, -2
	bnez t0, round_loop_\name

	# Add in initial block values.
	# 128 bit constant
	vadd.vx v0, v0, a3
	vadd.vx v1, v1, a4
	vadd.vx v2, v2, a6
	vadd.vx v3, v3, a7
	# Add key
	vadd.vx v4, v4, s0
	vadd.vx v5, v5, s1
	vadd.vx v6, v6, s2
	vadd.vx v7, v7, s3
	vadd.vx v8, v8, s4
	vadd.vx v9, v9, s5
	vadd.vx v10, v10, s6
	vadd.vx v11, v11, s7
	# Add counter
	vid.v v16
	vadd.vv v12, v12, v16
	vadd.vx v12, v12, a5
	# Add nonce
	vadd.vx v13, v13, s8
	vadd.vx v14, v14, s9
	vadd.vx v15, v15, s10

	# load in vector lanes with two strided segment loads
	# in case this is the final block, reset vl to full blocks
	vsetvli t5, t4, e32, m1, ta, ma
	li t0, 64
	vlsseg8e32.v v16, (a1), t0
	add a1, a1, 32
	vlsseg8e32.v v24, (a1), t0
	add a1, a1, -32

	# xor in state
	vxor.vv v16, v16, v0
	vxor.vv v17, v17, v1
	vxor.vv v18, v18, v2
	vxor.vv v19, v19, v3
	vxor.vv v20, v20, v4
	vxor.vv v21, v21, v5
	vxor.vv v22, v22, v6
	vxor.vv v23, v23, v7
	vxor.vv v24, v24, v8
	vxor.vv v25, v25, v9
	vxor.vv v26, v26, v10
	vxor.vv v27, v27, v11
	vxor.vv v28, v28, v12
	vxor.vv v29, v29, v13
	vxor.vv v30, v30, v14
	vxor.vv v31, v31, v15

	# write back out with 2 strided segment stores
	vssseg8e32.v v16, (a0), t0
	add a0, a0, 32
	vssseg8e32.v v24, (a0), t0
	add a0, a0, -32

	# update counters/pointers
	slli t5, t5, 6 # current VL in bytes
	add a0, a0, t5 # advance output pointer
	add a1, a1, t5 # advance input pointer
	sub a2, a2, t5 # decrement remaining bytes
	sub t3, t3, t2 # decrement remaining blocks
	sub t4, t4, t2 # decrement remaining blocks
	# TODO: crash if counter overflows
	add a5, a5, t2 # increment counter

	# loop again if we have remaining blocks
	bnez t3, encrypt_blocks_\name

	# restore registers
	addi sp, sp, 96
	ld s0, -8(sp)
	ld s1, -16(sp)
	ld s2, -24(sp)
	ld s3, -32(sp)
	ld s4, -40(sp)
	ld s5, -48(sp)
	ld s6, -56(sp)
	ld s7, -64(sp)
	ld s8, -72(sp)
	ld s9, -80(sp)
	ld s10, -88(sp)
	ret
.endm


# TODO: dynamically check for Zvkb extension at runtime and jump to the correct implementation.
# There doesn't seem to be a standard for sub-extension probing yet.
# Technically any chip that implements both V and K should include Zvkb, but qemu 10.0 doesn't support that.

vector_chacha20:
	CHACHA_FUNC_BODY emulated

#ifdef __riscv_zvkb
vector_chacha20_zvkb:
	CHACHA_FUNC_BODY native
#endif
