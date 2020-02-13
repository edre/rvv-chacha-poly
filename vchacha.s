.global instruction_counter
.global vector_chacha20
.global vlmax_u32

instruction_counter:
	rdinstret a0
	ret

vlmax_u32:
	li a0, -1
	vsetvli a0, a0, e32
	ret


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
vector_chacha20:
	# TODO: assert a2 is a multiple of 64.
	# TODO: even better, compute any final partial block, and xor it using scalar instructions
	# a2 = initial length in bytes
	# t3 = remaining length in 64-byte blocks
	# t1 = vl in 64-byte blocks
	srli t3, a2, 6
encrypt_blocks:
	# initialize vector state
	vsetvli t1, t3, e32
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
	lw t0, 0(a3)
	vmv.v.x v4, t0
	lw t0, 4(a3)
	vmv.v.x v5, t0
	lw t0, 8(a3)
	vmv.v.x v6, t0
	lw t0, 12(a3)
	vmv.v.x v7, t0
	lw t0, 16(a3)
	vmv.v.x v8, t0
	lw t0, 20(a3)
	vmv.v.x v9, t0
	lw t0, 24(a3)
	vmv.v.x v10, t0
	lw t0, 28(a3)
	vmv.v.x v11, t0
	# Load counter, and increment for each element
	vid.v v12
	vadd.vx v12, v12, a5
	# Load nonce
	ld t0, 0(a4)
	vmv.v.x v13, t0
	ld t0, 4(a4)
	vmv.v.x v14, t0
	ld t0, 8(a4)
	vmv.v.x v15, t0

	li t2, 10 # loop counter
round_loop:
	.macro vrotl a r
	vsll.vi v16, \a, \r
	vsrl.vi \a, \a, 32-\r
	vor.vv \a, \a, v16
	.endm

	.macro quarterround a b c d
	# a += b; d ^= a; d <<<= 16;
	vadd.vv \a, \a, \b
	vxor.vv \d, \d, \a
	vrotl \d, 16
	# c += d; b ^= c; b <<<= 12;
	vadd.vv \c, \c, \d
	vxor.vv \b, \b, \c
	vrotl \b, 12
	# a += b; d ^= a; d <<<= 8;
	vadd.vv \a, \a, \b
	vxor.vv \d, \d, \a
	vrotl \d, 8
	# c += d; b ^= c; b <<<= 7;
	vadd.vv \c, \c, \d
	vxor.vv \b, \b, \c
	vrotl \b, 7
	.endm

	# Mix columns. Could theoretically be done with VLMUL=4
	quarterround v0, v4, v8, v12
	quarterround v1, v5, v9, v13
	quarterround v2, v6, v10, v14
	quarterround v3, v7, v11, v15
	# Mix diagonals. Not VLMUL friendly
	quarterround v0, v5, v10, v15
	quarterround v1, v6, v11, v12
	quarterround v2, v7, v8, v13
	quarterround v3, v4, v9, v14
	
	addi t2, t2, -1
	bnez t2, round_loop

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
	lw t0, 	0(a3)
	vadd.vx v4, v4, t0
	lw t0, 4(a3)
	vadd.vx v5, v5, t0
	lw t0, 8(a3)
	vadd.vx v6, v6, t0
	lw t0, 12(a3)
	vadd.vx v7, v7, t0
	lw t0, 16(a3)
	vadd.vx v8, v8, t0
	lw t0, 20(a3)
	vadd.vx v9, v9, t0
	lw t0, 24(a3)
	vadd.vx v10, v10, t0
	lw t0, 28(a3)
	vadd.vx v11, v11, t0
	# Add counter
	vid.v v16
	vadd.vv v12, v12, v16
	vadd.vx v12, v12, a5
	# Load nonce
	ld t0, 0(a4)
	vadd.vx v13, v13, t0
	ld t0, 4(a4)
	vadd.vx v14, v14, t0
	ld t0, 8(a4)
	vadd.vx v15, v15, t0
	
	# out of inner loop, xor in state
	# load in vector lanes with two strided segment loads
	li t0, 64
	vlsseg8e.v v16, (a1), t0
	add a1, a1, 32
	vlsseg8e.v v24, (a1), t0
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
	vssseg8e.v v16, (a0), t0
	add a0, a0, 32
	vssseg8e.v v24, (a0), t0
	add a0, a0, -32

	# update counters/pointers
	slli t0, t1, 6 # current VL in bytes
	add a0, a0, t0 # advance output pointer
	add a1, a1, t0 # advance input pointer
	sub t3, t3, t1 # decrement remaining blocks
	# TODO: crash if counter overflows
	add a5, a5, t1 # increment counter

	# loop again if we have remaining blocks
	bne x0, t3, encrypt_blocks

	# TODO: if there is a partial block
	# extract the final words one at a time
	# There doesn't seem to be an indexed extract, so
	#  vslidedown.vx N
	#  vmv.x.s t3, vx
	#  sw sp[x], t3
	# Then use vl to copy the correct number of bytes

	ret
