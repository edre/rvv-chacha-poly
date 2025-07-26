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

.global vector_poly1305_init
.global vector_poly1305_blocks
.global vector_poly1305_single_blocks
.global vector_poly1305_emit
# poly1305
# Based on the obvious SIMD algorithm, described as Goll-Gueron here:
# https://eprint.iacr.org/2019/842.pdf
# Assumes VLEN is a power of 2, and that intermediate vsetvl will always return the max.
# Hash is defined simply, for 32-byte key split between 16-byte s and r:
# s + m[0:16] * r⁴ + m[16:32] * r³ + m[32:48] * r² + m[48:64] * r  mod  2¹³⁰ - 5
# Performant implementations represent 130 bit numbers as 5 26-bit numbers.
# Precomputation step:
#   Compute vector [r^VLMAX, ..., r³, r², r] ( 5 32-bit vectors)
#     Can be done in log2(VLMAX) poly multiplications
#   Extract scalar r^VLMAX (5 32-bit registers)
# Vector loop:
#   load segment (from the end) into 4 32-bit vectors
#   spread into standard 5 32-bit vector format
#   vector multiply into polynomial vector
#   vector add into sum so far
#   vector-scalar multiply polynomial vector with r^VLMAX
# Extract:
#   vector sum reduce polynomial vector into scalar
#   add to s
#   extract 16-byte hash

# r^vlmax limbs, and other scalar powers of r
#define R0 s0
#define R1 s1
#define R2 s2
#define R3 s3
#define R4 s4

# R scalars, but pre-multiplied by 5
#define R1x5 s5
#define R2x5 s6
#define R3x5 s7
#define R4x5 s8

# scalar accumulation. Only used after scalar r is finished.
#define ACCUM0 s0
#define ACCUM1 s1
#define ACCUM2 s2
#define ACCUM3 s3
#define ACCUM4 s4

# vector of powers of r, highest power in first element
# [r^vlmax, r^(vlmax-1), ... r^2, r]
#define VPOWER0 v6
#define VPOWER1 v7
#define VPOWER2 v8
#define VPOWER3 v9
#define VPOWER4 v10
#define VPOWER1x5 v27
#define VPOWER2x5 v28
#define VPOWER3x5 v29
#define VPOWER4x5 v30

# current accumulated vector state
#define VACCUM0 v1
#define VACCUM1 v2
#define VACCUM2 v3
#define VACCUM3 v4
#define VACCUM4 v5

# Widened vectors for 64 bit accumulation
#define VWIDE0 v12
#define VWIDE1 v14
#define VWIDE2 v16
#define VWIDE3 v18
#define VWIDE4 v20

#define VCARRY v22
#define VTMP0 v23
#define VTMP1 v24
#define VTMP2 v25
#define VTMP3 v26
#define VTMP4 v27
#define VTMP v28
#define VLOAD0 v11
#define VLOAD1 v12
#define VLOAD2 v13
#define VLOAD3 v14
#define VLOAD4 v15

# function arguments
#define CONTEXT a0
#define KEY a1
#define INPUT a1
#define LENGTH a2
#define PADBIT a3
#define MAC a1
#define NONCE a2

# loop tracking variables
#define INPUT_END a7
#define LIMB_MASK t6
#define CARRY t5
#define MAX_VL a5
#define BLOCKS_REMAINING a4
#define VL a6
#define INITIAL_VL a2
#define VTYPE s10
#define VTYPE_INC a4

# Generic 130-bit multiply/mod code
# Reads 5-limbed inputs from a and b, writes result to a
# Uses 5 e64,m2 d registers for accumulation
.macro vec_mul130 x a0 a1 a2 a3 a4 b0 b1 b2 b3 b4 b1x5 b2x5 b3x5 b4x5 v
	# Helpful diagram from http://loup-vaillant.fr/tutorials/poly1305-design
	#      a4      a3      a2      a1      a0
	# ×    b4      b3      b2      b1      b0
	# ---------------------------------------
	#   a4×b0   a3×b0   a2×b0   a1×b0   a0×b0
	# + a3×b1   a2×b1   a1×b1   a0×b1 5×a4×b1
	# + a2×b2   a1×b2   a0×b2 5×a4×b2 5×a3×b2
	# + a1×b3   a0×b3 5×a4×b3 5×a3×b3 5×a2×b3
	# + a0×b4 5×a4×b4 5×a3×b4 5×a2×b4 5×a1×b4
	# ---------------------------------------
	#      d4      d3      d2      d1      d0

	# Evaluated by rows to allow instructional parallelism in the accumulation.
	# b0 row
	vwmulu.\v VWIDE0, \a0, \b0
	vwmulu.\v VWIDE1, \a1, \b0
	vwmulu.\v VWIDE2, \a2, \b0
	vwmulu.\v VWIDE3, \a3, \b0
	vwmulu.\v VWIDE4, \a4, \b0

	# b1 row
	vwmaccu.\v VWIDE0, \b1x5, \a4
	vwmaccu.\v VWIDE1, \b1, \a0
	vwmaccu.\v VWIDE2, \b1, \a1
	vwmaccu.\v VWIDE3, \b1, \a2
	vwmaccu.\v VWIDE4, \b1, \a3

	# b2 row
	vwmaccu.\v VWIDE0, \b2x5, \a3
	vwmaccu.\v VWIDE1, \b2x5, \a4
	vwmaccu.\v VWIDE2, \b2, \a0
	vwmaccu.\v VWIDE3, \b2, \a1
	vwmaccu.\v VWIDE4, \b2, \a2
	
	# b3 row
	vwmaccu.\v VWIDE0, \b3x5, \a2
	vwmaccu.\v VWIDE1, \b3x5, \a3
	vwmaccu.\v VWIDE2, \b3x5, \a4
	vwmaccu.\v VWIDE3, \b3, \a0
	vwmaccu.\v VWIDE4, \b3, \a1

	# b4 row
	vwmaccu.\v VWIDE0, \b4x5, \a1
	vwmaccu.\v VWIDE1, \b4x5, \a2
	vwmaccu.\v VWIDE2, \b4x5, \a3
	vwmaccu.\v VWIDE3, \b4x5, \a4
	vwmaccu.\v VWIDE4, \b4, \a0

	# Carry propagation
	# logic copied from https://github.com/floodyberry/poly1305-donna
	.macro carry_prop\x a d
	vwaddu.wv \d, \d, VCARRY
	vnsrl.wi VCARRY, \d, 26
	vnsrl.wi \a, \d, 0
	vand.vx \a, \a, LIMB_MASK
	.endm

	vmv.v.i VCARRY, 0
	carry_prop\x \a0, VWIDE0
	carry_prop\x \a1, VWIDE1
	carry_prop\x \a2, VWIDE2
	carry_prop\x \a3, VWIDE3
	carry_prop\x \a4, VWIDE4

	# wraparound carry continue
	vsll.vi VTMP, VCARRY, 2
	vadd.vv \a0, \a0, VTMP
	vadd.vv \a0, \a0, VCARRY
	# boring stops carrying here, but that fails random tests
	vsrl.vi VCARRY, \a0, 26
	vand.vx \a0, \a0, LIMB_MASK
	vadd.vv \a1, \a1, VCARRY

.endm

# Scalar 130-bit a0-4 = a0-4 * a0-4
.macro scalar_mul130 a0 a1 a2 a3 a4 a3x5 a4x5 d0 d1 d2 d3 d4 tmp
	# d0 column
	mul \d0, \a1, \a4x5
	mul \tmp, \a2, \a3x5
	add \d0, \d0, \tmp
	mul \tmp, \a0, \a0
	sh1add \d0, \d0, \tmp

	# d1 column
	mul \d1, \a1, \a0
	mul \tmp, \a2, \a4x5
	add \d1, \d1, \tmp
	mul \tmp, \a3x5, \a3
	sh1add \d1, \d1, \tmp

	# d2 column
	mul \d2, \a2, \a0
	mul \tmp, \a3x5, \a4
	add \d2, \d2, \tmp
	mul \tmp, \a1, \a1
	sh1add \d2, \d2, \tmp

	# d3 column
	mul \d3, \a3, \a0
	mul \tmp, \a1, \a2
	add \d3, \d3, \tmp
	mul \tmp, \a4x5, \a4
	sh1add \d3, \d3, \tmp

	# d4 column
	mul \d4, \a4, \a0
	mul \tmp, \a1, \a3
	add \d4, \d4, \tmp
	mul \tmp, \a2, \a2
	sh1add \d4, \d4, \tmp

	# Carry propagation
	# logic copied from https://github.com/floodyberry/poly1305-donna
	.macro carry_prop_scalar a d
	add \d, \d, CARRY
	srli CARRY, \d, 26
	and \a, \d, LIMB_MASK
	.endm

	li CARRY, 0
	carry_prop_scalar \a0, \d0
	carry_prop_scalar \a1, \d1
	carry_prop_scalar \a2, \d2
	carry_prop_scalar \a3, \d3
	carry_prop_scalar \a4, \d4

	# wraparound carry continue
	sh2add \a0, CARRY, \a0
	add \a0, \a0, CARRY
	# carry as much as the other mul code
	srli CARRY, \a0, 26
	and \a0, \a0, LIMB_MASK
	add \a1, \a1, CARRY
.endm

.macro scalar_extract_limbs i0 i1 r0 r1 r2 r3 r4
	and \r0, \i0, LIMB_MASK
	srli \r1, \i0, 26
	and \r1, \r1, LIMB_MASK
	srli \r2, \i0, 52
	slli \i0, \i1, 12
	or \r2, \r2, \i0
	and \r2, \r2, LIMB_MASK
	srli \r3, \i1, 14
	and \r3, \r3, LIMB_MASK
	srli \r4, \i1, 40
.endm


# openssl gives 192 bytes of scratch space for assembly implementations,
# not counting nonce or partial block buffer. This is exactly enough for:
# state struct {
#   uint32_t[5] previous accumulated state // offset 0
#   uint32_t[8][5] 8-element powers of r vector, in 5 limbs // offset 20
#   bool cached_powers // offset 180
# }

# void poly1305_init(void *ctx, const unsigned char key[16])
vector_poly1305_init:
	# save registers
	sd s0, -8(sp)
	sd s1, -16(sp)
	sd s2, -24(sp)
	sd s3, -32(sp)
	sd s4, -40(sp)

	li LIMB_MASK, 0x3ffffff

	# load R and spread to 5 26-bit limbs
	ld t0, 0(KEY)
	ld t1, 8(KEY)
	li t2, 0x0ffffffc0fffffff
	and t0, t0, t2
	li t2, 0x0ffffffc0ffffffc
	and t1, t1, t2
	scalar_extract_limbs t0 t1 R0 R1 R2 R3 R4

	# store r^1 where it will live at the end of the powers of r
	vsetivli MAX_VL, 8, e32, m1, ta, ma
	# reduced t0*20
	sh2add t0, MAX_VL, MAX_VL
	sh2add t0, t0, CONTEXT

	sw R0, 0(t0)
	sw R1, 4(t0)
	sw R2, 8(t0)
	sw R3, 12(t0)
	sw R4, 16(t0)

	# zero initial accumulation
	sd zero, 0(CONTEXT)
	sd zero, 8(CONTEXT)
	sw zero, 16(CONTEXT)
	# zero cached_powers bit
	sw zero, 180(CONTEXT)

	# restore registers
	ld s0, -8(sp)
	ld s1, -16(sp)
	ld s2, -24(sp)
	ld s3, -32(sp)
	ld s4, -40(sp)
	ret

# void poly1305_blocks(void *ctx, const unsigned char *inp, size_t len, u32 padbit)
vector_poly1305_blocks:
	# save registers
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
	
	beqz LENGTH, blocks_return

	# check to see if powers are already cached
	lw t0, 180(CONTEXT)
	bnez t0, do_the_multi_blocks
	
	vsetivli MAX_VL, 8, e32, m1, ta, ma
	# reduced t0*20
	sh2add t0, MAX_VL, MAX_VL
	sh2add t0, t0, CONTEXT
	lw R0, 0(t0)
	lw R1, 4(t0)
	lw R2, 8(t0)
	lw R3, 12(t0)
	lw R4, 16(t0)

	# pre-multiplied-by-5 scalars
	sh2add R1x5, R1, R1
	sh2add R2x5, R2, R2
	sh2add R3x5, R3, R3
	sh2add R4x5, R4, R4

	# move r^1 to second element
	vsetivli zero, 2, e32, m1, ta, ma
	vmv.v.x VPOWER0, R0
	vmv.v.x VPOWER1, R1
	vmv.v.x VPOWER2, R2
	vmv.v.x VPOWER3, R3
	vmv.v.x VPOWER4, R4

	# Do first iteration manually, as scalar squaring is faster than vector multiplying.

	# scalar-scalar 130bit mul: R = R * R
	scalar_mul130 R0 R1 R2 R3 R4 R3x5 R4x5 t0 t1 t2 t3 t4 s9

	# move r^2 to first element
	vsetivli zero, 1, e32, m1, tu, ma
	vmv.v.x VPOWER0, R0
	vmv.v.x VPOWER1, R1
	vmv.v.x VPOWER2, R2
	vmv.v.x VPOWER3, R3
	vmv.v.x VPOWER4, R4

	vsetivli MAX_VL, 8, e32, m1, tu, ma
	li VL, 2

precomp:
	# Duplicate elements in each vector lane.
	# [r^2, r^1] -> [r^2, r^1, r^2, r^1]
	slli t0, VL, 1
	vsetvli zero, t0, e32, m1, ta, ma
	vmv.v.v VTMP0, VPOWER0
	vmv.v.v VTMP1, VPOWER1
	vmv.v.v VTMP2, VPOWER2
	vmv.v.v VTMP3, VPOWER3
	vmv.v.v VTMP4, VPOWER4
	vslideup.vx VPOWER0, VTMP0, VL
	vslideup.vx VPOWER1, VTMP1, VL
	vslideup.vx VPOWER2, VTMP2, VL
	vslideup.vx VPOWER3, VTMP3, VL
	vslideup.vx VPOWER4, VTMP4, VL

	# pre-multiplied-by-5 scalars
	sh2add R1x5, R1, R1
	sh2add R2x5, R2, R2
	sh2add R3x5, R3, R3
	sh2add R4x5, R4, R4
	vsetvli zero, VL, e32, m1, tu, ma
	# vector-scalar 130bit mul on the first half of the elements: VPOWER = VPOWER * R
	# [r^2, r^1, r^2, r^1]
	# *r^2 *r^2
	vec_mul130 precomp VPOWER0 VPOWER1 VPOWER2 VPOWER3 VPOWER4 R0 R1 R2 R3 R4 R1x5 R2x5 R3x5 R4x5 vx

	# extract new highest power from first element
	vmv.x.s R0, VPOWER0
	vmv.x.s R1, VPOWER1
	vmv.x.s R2, VPOWER2
	vmv.x.s R3, VPOWER3
	vmv.x.s R4, VPOWER4

	# end of precomp loop:
	slli VL, VL, 1
	blt VL, MAX_VL, precomp

	# store state
	# power of r vector limbs
	add t0, CONTEXT, 20
	vsetvli zero, VL, e32, m1, ta, ma
	vsseg5e32.v VPOWER0, (t0)
	# mark cached
	li t0, 1
	sw t0, 180(CONTEXT)

do_the_multi_blocks:
	li LIMB_MASK, 0x3ffffff
	# load state
	lw R0, 20(CONTEXT)
	lw R1, 24(CONTEXT)
	lw R2, 28(CONTEXT)
	lw R3, 32(CONTEXT)
	lw R4, 36(CONTEXT)
	# pre-multiplied by 5 scalars
	sh2add R1x5, R1, R1
	sh2add R2x5, R2, R2
	sh2add R3x5, R3, R3
	sh2add R4x5, R4, R4
	# shift pad bit into position
	slli PADBIT, PADBIT, 24

	# The vector unit may be larger than the fixed context struct, so we cap MAX_VL at 8.
	# TODO: Perhaps we can dynamically generate the larger powers of r to fill
	# the larger VL if the input is long enough.
	vsetivli MAX_VL, 8, e32, m1, ta, ma
	add INPUT_END, INPUT, LENGTH
	srli BLOCKS_REMAINING, LENGTH, 4

	# We need to do vsetvl manually as we're potentially 
	# using a smaller max than the vector unit can handle.
	minu INITIAL_VL, BLOCKS_REMAINING, MAX_VL
	vsetvli INITIAL_VL, INITIAL_VL, e32, m1, tu, ma
	# set up state as initial zero step
	vmv.v.i VACCUM0, 0
	vmv.v.i VACCUM1, 0
	vmv.v.i VACCUM2, 0
	vmv.v.i VACCUM3, 0
	vmv.v.i VACCUM4, 0
	# add scalar accumulation to first vector element
	vsetivli zero, 1, e32, m1, tu, ma
	vlseg5e32.v VACCUM0, (CONTEXT)
	vsetvli VL, INITIAL_VL, e32, m1, tu, ma

vector_loop:
	# load in new data:
	vlseg4e32.v VLOAD0, (INPUT)
	# adjust pointers/counters
	slli t0, VL, 4
	add INPUT, INPUT, t0
	sub BLOCKS_REMAINING, BLOCKS_REMAINING, VL

	# From VLOAD, separate out into 5 26-bit limbs into VTMP
	vand.vx VTMP0, VLOAD0, LIMB_MASK
	vsrl.vi VLOAD0, VLOAD0, 26
	vsll.vi VTMP, VLOAD1, 6
	vadd.vv VLOAD0, VLOAD0, VTMP
	vand.vx VTMP1, VLOAD0, LIMB_MASK
	vsrl.vi VLOAD1, VLOAD1, 20
	vsll.vi VTMP, VLOAD2, 12
	vadd.vv VLOAD1, VLOAD1, VTMP
	vand.vx VTMP2, VLOAD1, LIMB_MASK
	vsrl.vi VLOAD2, VLOAD2, 14
	vsll.vi VTMP, VLOAD3, 18
	vadd.vv VLOAD2, VLOAD2, VTMP
	vand.vx VTMP3, VLOAD2, LIMB_MASK
	vsrl.vi VTMP4, VLOAD3, 8
	# add leading bit
	vadd.vx VTMP4, VTMP4, PADBIT

	# add into state
	vadd.vv VACCUM0, VACCUM0, VTMP0
	vadd.vv VACCUM1, VACCUM1, VTMP1
	vadd.vv VACCUM2, VACCUM2, VTMP2
	vadd.vv VACCUM3, VACCUM3, VTMP3
	vadd.vv VACCUM4, VACCUM4, VTMP4

	# End final loop before batch multiply.
	bge INPUT, INPUT_END, rotate_powers

	# Manual vsetvl
	minu VL, BLOCKS_REMAINING, MAX_VL
	vsetvli VL, VL, e32, m1, tu, ma
	## multiply by r^vlmax
	vec_mul130 vx VACCUM0 VACCUM1 VACCUM2 VACCUM3 VACCUM4 R0 R1 R2 R3 R4 R1x5 R2x5 R3x5 R4x5 vx
	j vector_loop

rotate_powers:
	add t2, CONTEXT, 20
	sub t0, MAX_VL, VL
	# If the final block is full or we never had a full block, skip the rotation.
	beq VL, MAX_VL, tail_rotate_powers
	blt INITIAL_VL, MAX_VL, tail_rotate_powers

	# load higher power of r vector limbs
	vsetivli zero, 8, e32, m1, ta, ma
	vlseg5e32.v VLOAD0, (t2)
	# rotate them to end at the last VL
	vslidedown.vx VPOWER0, VLOAD0, t0
	vslidedown.vx VPOWER1, VLOAD1, t0
	vslidedown.vx VPOWER2, VLOAD2, t0
	vslidedown.vx VPOWER3, VLOAD3, t0
	vslidedown.vx VPOWER4, VLOAD4, t0
	vslideup.vx VPOWER0, VLOAD0, VL
	vslideup.vx VPOWER1, VLOAD1, VL
	vslideup.vx VPOWER2, VLOAD2, VL
	vslideup.vx VPOWER3, VLOAD3, VL
	vslideup.vx VPOWER4, VLOAD4, VL
	j mul_powers_of_r

tail_rotate_powers:
	# load the lower powers into the lower elements
	# reduced t2+=t0*20
	sh2add t0, t0, t0
	sh2add t2, t0, t2
	vsetvli zero, VL, e32, m1, ta, ma
	vlseg5e32.v VPOWER0, (t2)

mul_powers_of_r:
	vsetvli zero, INITIAL_VL, e32, m1, ta, ma
	# multiply in powers of r vector
	vsll.vi VPOWER1x5, VPOWER1, 2
	vsll.vi VPOWER2x5, VPOWER2, 2
	vsll.vi VPOWER3x5, VPOWER3, 2
	vsll.vi VPOWER4x5, VPOWER4, 2
	vadd.vv VPOWER1x5, VPOWER1x5, VPOWER1
	vadd.vv VPOWER2x5, VPOWER2x5, VPOWER2
	vadd.vv VPOWER3x5, VPOWER3x5, VPOWER3
	vadd.vv VPOWER4x5, VPOWER4x5, VPOWER4
	vec_mul130 vv VACCUM0 VACCUM1 VACCUM2 VACCUM3 VACCUM4 VPOWER0 VPOWER1 VPOWER2 VPOWER3 VPOWER4 VPOWER1x5 VPOWER2x5 VPOWER3x5 VPOWER4x5 vv

	# vector reduction
	vmv.v.i VTMP0, 0
	vmv.v.i VTMP1, 0
	vmv.v.i VTMP2, 0
	vmv.v.i VTMP3, 0
	vmv.v.i VTMP4, 0
	vredsum.vs VTMP0, VACCUM0, VTMP0
	vredsum.vs VTMP1, VACCUM1, VTMP1
	vredsum.vs VTMP2, VACCUM2, VTMP2
	vredsum.vs VTMP3, VACCUM3, VTMP3
	vredsum.vs VTMP4, VACCUM4, VTMP4
	# extract to scalars
	vmv.x.s ACCUM0, VTMP0
	vmv.x.s ACCUM1, VTMP1
	vmv.x.s ACCUM2, VTMP2
	vmv.x.s ACCUM3, VTMP3
	vmv.x.s ACCUM4, VTMP4

	# carry through
	li CARRY, 0
	.macro carry_scalar accum
	add \accum, \accum, CARRY
	srli CARRY, \accum, 26
	and \accum, \accum, LIMB_MASK
	.endm

	carry_scalar ACCUM0
	carry_scalar ACCUM1
	carry_scalar ACCUM2
	carry_scalar ACCUM3
	carry_scalar ACCUM4
	# carry *= 5
	sh2add CARRY, CARRY, CARRY
	carry_scalar ACCUM0
	carry_scalar ACCUM1
	carry_scalar ACCUM2
	carry_scalar ACCUM3
	carry_scalar ACCUM4

	sw ACCUM0, 0(CONTEXT)
	sw ACCUM1, 4(CONTEXT)
	sw ACCUM2, 8(CONTEXT)
	sw ACCUM3, 12(CONTEXT)
	sw ACCUM4, 16(CONTEXT)

blocks_return:
	# restore registers
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
	ret

# same signature as the other blocks function, but computes one block at a time to optimize for smaller inputs
# void poly1305_blocks(void *ctx, const unsigned char *inp, size_t len, u32 padbit)
vector_poly1305_single_blocks:
	# save registers
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
	# leave 40 bytes of stack space
	add sp, sp, -136

	li LIMB_MASK, 0x3ffffff
	# find r^1 in saved powers of r tail
	vsetivli MAX_VL, 8, e32, m1, ta, ma
	# reduced t0*20
	sh2add t0, MAX_VL, MAX_VL
	sh2add t0, t0, CONTEXT
	# our VL for the rest of the function:
	# 5 32-bit limbs, with LMUL=2 iff VLEN=128
	li VTYPE, 0xd0
	slti t1, MAX_VL, 8
	add VTYPE, VTYPE, t1
	li VL, 5
	li VTYPE_INC, 0x9
	vsetvl zero, VL, VTYPE
	vle32.v VWIDE0, (t0)
	# precompute r*5
	lw R1, 4(t0)
	lw R2, 8(t0)
	lw R3, 12(t0)
	lw R4, 16(t0)
	sh2add R1x5, R1, R1
	sh2add R2x5, R2, R2
	sh2add R3x5, R3, R3
	sh2add R4x5, R4, R4
	# precompute offset multipliers, preshifted
	vslide1up.vx VWIDE1, VWIDE0, R4x5
	vslide1up.vx VWIDE2, VWIDE1, R3x5
	vslide1up.vx VWIDE3, VWIDE2, R2x5
	vslide1up.vx VWIDE4, VWIDE3, R1x5

	lw ACCUM0, 0(CONTEXT)
	lw ACCUM1, 4(CONTEXT)
	lw ACCUM2, 8(CONTEXT)
	lw ACCUM3, 12(CONTEXT)
	lw ACCUM4, 16(CONTEXT)
	# shift pad bit into position
	slli PADBIT, PADBIT, 24

	# loop target
	add INPUT_END, INPUT, LENGTH
	j end_single_block_loop

single_block_loop:
	# Load block and split into 5 limbs (s5-9)
	ld t0, 0(INPUT)
	ld t1, 8(INPUT)
	add INPUT, INPUT, 16
	scalar_extract_limbs t0 t1 s5 s6 s7 s8 s9
	# pad bit
	or s9, s9, PADBIT
	# Add into accumulator
	add ACCUM0, ACCUM0, s5
	add ACCUM1, ACCUM1, s6
	add ACCUM2, ACCUM2, s7
	add ACCUM3, ACCUM3, s8
	add ACCUM4, ACCUM4, s9

	# vector multiply into widened destination
	vwmulu.vx VTMP, VWIDE0, ACCUM0
	vwmaccu.vx VTMP, ACCUM1, VWIDE1
	vwmaccu.vx VTMP, ACCUM2, VWIDE2
	vwmaccu.vx VTMP, ACCUM3, VWIDE3
	vwmaccu.vx VTMP, ACCUM4, VWIDE4

	# extract to 64-bit scalars, via the stack
	add VTYPE, VTYPE, VTYPE_INC
	vsetvl zero, VL, VTYPE
	vse64.v VTMP, (sp)
	sub VTYPE, VTYPE, VTYPE_INC
	vsetvl zero, VL, VTYPE
	ld ACCUM0, 0(sp)
	ld ACCUM1, 8(sp)
	ld ACCUM2, 16(sp)
	ld ACCUM3, 24(sp)
	ld ACCUM4, 32(sp)
	# carry through
	li CARRY, 0
	carry_scalar ACCUM0
	carry_scalar ACCUM1
	carry_scalar ACCUM2
	carry_scalar ACCUM3
	carry_scalar ACCUM4
	# carry *= 5
	sh2add CARRY, CARRY, CARRY
	carry_scalar ACCUM0
	carry_scalar ACCUM1
	carry_scalar ACCUM2
	carry_scalar ACCUM3
	carry_scalar ACCUM4

end_single_block_loop:
	blt INPUT, INPUT_END, single_block_loop

	# save new accumulator
	sw ACCUM0, 0(CONTEXT)
	sw ACCUM1, 4(CONTEXT)
	sw ACCUM2, 8(CONTEXT)
	sw ACCUM3, 12(CONTEXT)
	sw ACCUM4, 16(CONTEXT)

return:
	# restore registers
	add sp, sp, 136
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

# void poly1305_emit(void *ctx, unsigned char mac[16],
#                           const u32 nonce[4])
vector_poly1305_emit:
	sd s0, -8(sp)
	sd s1, -16(sp)
	sd s2, -24(sp)
	sd s3, -32(sp)
	sd s4, -40(sp)

	# load final accumulation
	lw ACCUM0, 0(CONTEXT)
	lw ACCUM1, 4(CONTEXT)
	lw ACCUM2, 8(CONTEXT)
	lw ACCUM3, 12(CONTEXT)
	lw ACCUM4, 16(CONTEXT)
	# collapse into contiguous 128 bits (t0,t1)
	slli t5, ACCUM1, 26
	or t0, ACCUM0, t5
	slli t5, ACCUM2, 52
	or t0, t0, t5
	srli t1, ACCUM2, 12
	slli t5, ACCUM3, 14
	or t1, t1, t5
	slli t5, ACCUM4, 40
	or t1, t1, t5
	# add in other half of key (after the carry)
	ld t2, 0(NONCE)
	ld t3, 8(NONCE)
	add t0, t0, t2
	sltu t2, t0, t2
	add t1, t1, t2
	add t1, t1, t3

	# write final signature
	sd t0, 0(MAC)
	sd t1, 8(MAC)

	ld s0, -8(sp)
	ld s1, -16(sp)
	ld s2, -24(sp)
	ld s3, -32(sp)
	ld s4, -40(sp)
	ret
