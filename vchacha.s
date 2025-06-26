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

.global instruction_counter
.global vector_chacha20
.global vector_chacha20_zvkb
.global vlmax_u32

instruction_counter:
	rdinstret a0
	ret

vlmax_u32:
	vsetvli a0, x0, e32, m1, ta, ma
	ret


.macro vrotl_native a, r
vror.vi \a, \a, 32-\r
.endm

.macro vrotl_emulated a, r
vsll.vi v16, \a, \r
vsrl.vi \a, \a, 32-\r
vor.vv \a, \a, v16
.endm

.macro quarterround name a b c d
	# a += b; d ^= a; d <<<= 16;
	vadd.vv \a, \a, \b
	vxor.vv \d, \d, \a
	vrotl_\name \d, 16
	# c += d; b ^= c; b <<<= 12;
	vadd.vv \c, \c, \d
	vxor.vv \b, \b, \c
	vrotl_\name \b, 12
	# a += b; d ^= a; d <<<= 8;
	vadd.vv \a, \a, \b
	vxor.vv \d, \d, \a
	vrotl_\name \d, 8
	# c += d; b ^= c; b <<<= 7;
	vadd.vv \c, \c, \d
	vxor.vv \b, \b, \c
	vrotl_\name \b, 7
.endm

.macro doubleround name
	# Mix columns.
	quarterround \name, v0, v4, v8, v12
	quarterround \name, v1, v5, v9, v13
	quarterround \name, v2, v6, v10, v14
	quarterround \name, v3, v7, v11, v15
	# Mix diagonals.
	quarterround \name, v0, v5, v10, v15
	quarterround \name, v1, v6, v11, v12
	quarterround \name, v2, v7, v8, v13
	quarterround \name, v3, v4, v9, v14
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
	# t1 = vl in 64-byte blocks
	srli t4, a2, 6
	addi t0, a2, 63
	srli t3, t0, 6

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

encrypt_blocks_\name:
	# initialize vector state
	vsetvli t1, t3, e32, m1, ta, ma
	# Load 128 bit constant
	li t0, 0x61707865 # "expa" little endian
	vmv.v.x v0, t0
	li t0, 0x3320646e # "nd 3" little endian
	vmv.v.x v1, t0
	li t0, 0x79622d32 # "2-by" little endian
	vmv.v.x v2, t0
	li t0, 0x6b206574 # "te k" little endian
	vmv.v.x v3, t0
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
	doubleround \name
	doubleround \name
	doubleround \name
	doubleround \name
	doubleround \name
	doubleround \name
	doubleround \name
	doubleround \name
	doubleround \name
	doubleround \name

	# Add in initial block values.
	# 128 bit constant
	li t0, 0x61707865 # "expa" little endian
	vadd.vx v0, v0, t0
	li t0, 0x3320646e # "nd 3" little endian
	vadd.vx v1, v1, t0
	li t0, 0x79622d32 # "2-by" little endian
	vadd.vx v2, v2, t0
	li t0, 0x6b206574 # "te k" little endian
	vadd.vx v3, v3, t0
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
	slli t0, t5, 6 # current VL in bytes
	add a0, a0, t0 # advance output pointer
	add a1, a1, t0 # advance input pointer
	sub a2, a2, t0 # decrement remaining bytes
	sub t3, t3, t1 # decrement remaining blocks
	sub t4, t4, t1 # decrement remaining blocks
	# TODO: crash if counter overflows
	add a5, a5, t1 # increment counter

	# loop again if we have remaining blocks
	bnez t3, encrypt_blocks_\name

	# we're done if there are no more remaining bytes from a partial block
	beqz a2, return_\name

	# to get the remaining partial block, we transfer the nth element of
	# all the state vectors into contiguous stack memory with vsseg, then
	# read them with byte-granularity vl

	# reconstruct vl for all computed blocks
	add t0, t3, t1
	vsetvli t0, t0, e32, m1, ta, ma
	add t0, t0, -1

	# use a masked vsseg instead of sliding everything down?
	# both options seem like they might touch a lot of vector state...
	vslidedown.vx v16, v0, t0
	vslidedown.vx v17, v1, t0
	vslidedown.vx v18, v2, t0
	vslidedown.vx v19, v3, t0
	vslidedown.vx v20, v4, t0
	vslidedown.vx v21, v5, t0
	vslidedown.vx v22, v6, t0
	vslidedown.vx v23, v7, t0
	vslidedown.vx v24, v8, t0
	vslidedown.vx v25, v9, t0
	vslidedown.vx v26, v10, t0
	vslidedown.vx v27, v11, t0
	vslidedown.vx v28, v12, t0
	vslidedown.vx v29, v13, t0
	vslidedown.vx v30, v14, t0
	vslidedown.vx v31, v15, t0
	li t0, 1
	vsetvli zero, t0, e32, m1, ta, ma
	addi t0, sp, -64
	addi t1, sp, -32
	vsseg8e32.v v16, (t0)
	vsseg8e32.v v24, (t1)

	vsetvli a2, a2, e8, m8, ta, ma
	vle8.v v0, (a1)
	vle8.v v8, (t0)
	vxor.vv v0, v0, v8
	vse8.v v0, (a0)

return_\name:
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

vector_chacha20_zvkb:
	CHACHA_FUNC_BODY native
