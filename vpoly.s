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
.global vector_poly1305_emit
# poly1305
# Based on the obvious SIMD algorithm, described as Goll-Gueron here:
# https://eprint.iacr.org/2019/842.pdf
# Assumes VLEN is a power of 2, and that intermediate vsetvl will always return the max.
# Hash is defined simply, for 32-byte key split between 16-byte s and r:
# s + m[0:16] * r⁴ + m[16:32] * r³ + m[32:48] * r² + m[48:64] * r  mod  2¹³⁰ - 5
# Performant implementations represent 130 bit numbers as 5 26-bit numbers.
# Precomputation step:
#   Compute vector [r, r², r³, r⁴, ...] ( 5 32-bit vectors)
#   Compute scalar r^VLMAX (5 32-bit registers)
#   This can be done in 2*log2(VLMAX) multiplications:
#   i = 1; m = r; v = r
#   while i < VLMAX:
#       v *= m (masking out the last i elements)
#       m *= m
#       i <<= 1
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

# Generic 130-bit multiply/mod code
# Reads 5-limbed inputs from a and b, writes result to a
# Uses 5 e64,m2 d registers for accumulation
.macro vec_mul130 x a0 a1 a2 a3 a4 b0 b1 b2 b3 b4 b51 b52 b53 b54 d0 d1 d2 d3 d4 carry tmp v mask=""
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
	vwmulu.\v \d0, \a0, \b0 \mask
	vwmulu.\v \d1, \a1, \b0 \mask
	vwmulu.\v \d2, \a2, \b0 \mask
	vwmulu.\v \d3, \a3, \b0 \mask
	vwmulu.\v \d4, \a4, \b0 \mask

	# b1 row
	vwmaccu.\v \d0, \b51, \a4 \mask
	vwmaccu.\v \d1, \b1, \a0 \mask
	vwmaccu.\v \d2, \b1, \a1 \mask
	vwmaccu.\v \d3, \b1, \a2 \mask
	vwmaccu.\v \d4, \b1, \a3 \mask

	# b2 row
	vwmaccu.\v \d0, \b52, \a3 \mask
	vwmaccu.\v \d1, \b52, \a4 \mask
	vwmaccu.\v \d2, \b2, \a0 \mask
	vwmaccu.\v \d3, \b2, \a1 \mask
	vwmaccu.\v \d4, \b2, \a2 \mask
	
	# b3 row
	vwmaccu.\v \d0, \b53, \a2 \mask
	vwmaccu.\v \d1, \b53, \a3 \mask
	vwmaccu.\v \d2, \b53, \a4 \mask
	vwmaccu.\v \d3, \b3, \a0 \mask
	vwmaccu.\v \d4, \b3, \a1 \mask

	# b4 row
	vwmaccu.\v \d0, \b54, \a1 \mask
	vwmaccu.\v \d1, \b54, \a2 \mask
	vwmaccu.\v \d2, \b54, \a3 \mask
	vwmaccu.\v \d3, \b54, \a4 \mask
	vwmaccu.\v \d4, \b4, \a0 \mask

	# Carry propagation
	# logic copied from https://github.com/floodyberry/poly1305-donna
	li t0, 0x3ffffff
	.macro carry_prop\x a d
	vwaddu.wv \d, \d, \carry \mask
	vnsrl.wi \carry, \d, 26 \mask
	vnsrl.wi \a, \d, 0 \mask
	vand.vx \a, \a, t0 \mask
	.endm

	vmv.v.i \carry, 0
	carry_prop\x \a0, \d0
	carry_prop\x \a1, \d1
	carry_prop\x \a2, \d2
	carry_prop\x \a3, \d3
	carry_prop\x \a4, \d4

	# wraparound carry continue
	vsll.vi \tmp, \carry, 2 \mask
	vadd.vv \a0, \a0, \tmp \mask
	vadd.vv \a0, \a0, \carry \mask
	# boring stops carrying here, but that fails random tests
	vsrl.vi \carry, \a0, 26 \mask
	vand.vx \a0, \a0, t0 \mask
	vadd.vv \a1, \a1, \carry \mask

	.endm

# Scalar 130-bit a0-4 = a0-4 * a0-4
.macro scalar_mul130 x a0 a1 a2 a3 a4 a51 a52 a53 a54 d0 d1 d2 d3 d4 carry tmp
	# d0 column
	mul \d0, \a1, \a54
	mul \tmp, \a2, \a53
	add \d0, \d0, \tmp
	slli \d0, \d0, 1
	mul \tmp, \a0, \a0
	add \d0, \d0, \tmp

	# d1 column
	mul \d1, \a1, \a0
	mul \tmp, \a2, \a54
	add \d1, \d1, \tmp
	slli \d1, \d1, 1
	mul \tmp, \a53, \a3
	add \d1, \d1, \tmp

	# d2 column
	mul \d2, \a2, \a0
	mul \tmp, \a53, \a4
	add \d2, \d2, \tmp
	slli \d2, \d2, 1
	mul \tmp, \a1, \a1
	add \d2, \d2, \tmp

	# d3 column
	mul \d3, \a3, \a0
	mul \tmp, \a1, \a2
	add \d3, \d3, \tmp
	slli \d3, \d3, 1
	mul \tmp, \a54, \a4
	add \d3, \d3, \tmp

	# d4 column
	mul \d4, \a4, \a0
	mul \tmp, \a1, \a3
	add \d4, \d4, \tmp
	slli \d4, \d4, 1
	mul \tmp, \a2, \a2
	add \d4, \d4, \tmp

	# Carry propagation
	# logic copied from https://github.com/floodyberry/poly1305-donna
	li \tmp, 0x3ffffff
	.macro carry_prop_scalar\x a d
	add \d, \d, \carry
	srli \carry, \d, 26
	and \a, \d, \tmp
	.endm

	li \carry, 0
	carry_prop_scalar\x \a0, \d0
	carry_prop_scalar\x \a1, \d1
	carry_prop_scalar\x \a2, \d2
	carry_prop_scalar\x \a3, \d3
	carry_prop_scalar\x \a4, \d4

	# wraparound carry continue
	slli \tmp, \carry, 2
	add \a0, \a0, \tmp
	add \a0, \a0, \carry
	# carry as much as the other mul code
	srli \carry, \a0, 26
	li \tmp, 0x3ffffff
	and \a0, \a0, \tmp
	add \a1, \a1, \carry

	# Store a*5 registers for next time
	slli \a51, \a1, 2
	add \a51, \a51, \a1
	slli \a52, \a2, 2
	add \a52, \a52, \a2
	slli \a53, \a3, 2
	add \a53, \a53, \a3
	slli \a54, \a4, 2
	add \a54, \a54, \a4

.endm

.macro scalar_extract_limbs i0 i1 r0 r1 r2 r3 r4 tmp
	li \tmp, 0x3ffffff
	and \r0, \i0, \tmp
	srli \r1, \i0, 26
	and \r1, \r1, \tmp
	srli \r2, \i0, 52
	slli \i0, \i1, 12
	or \r2, \r2, \i0
	and \r2, \r2, \tmp
	srli \r3, \i1, 14
	and \r3, \r3, \tmp
	srli \r4, \i1, 40
.endm

.macro scalar_compress_limbs r0 r1 r2 r3 r4 tmp
	slli \tmp, \r1, 26
	or \r0, \r0, \tmp
	slli \tmp, \r2, 52
	or \r0, \r0, \tmp
	srli \r1, \r2, 12
	slli \tmp, \r3, 14
	or \r1, \r1, \tmp
	slli \tmp, \r4, 40
	or \r1, \r1, \tmp
.endm


# Argument mappings
# TODO: define macros to not have to remember these assignments
# r^vlmax: s0, s1, s2, s3, s4
# [r^vlmax, r^(vlmax-1), ... r^2, r]: v6, v7, v8, v9, v10
# current accumulated vector state: v1, v2, v3, v4, v5

# openssl gives 192 bytes of scratch space for assembly implementations,
# not counting nonce or partial block buffer. This is exactly enough for:
# state struct {
#   uint64_t[2] previous accumulated state // offset 0
#   uint64_t[2] r^vlmax // offset 16
#   uint32_t[8][5] 8-element powers of r vector, in 5 limbs // offset 32
# }

# void poly1305_init(void *ctx, const unsigned char key[16])
vector_poly1305_init:
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

	ld t0, 0(a1)
	ld t1, 8(a1)
	sd t0, 0(a0)
	sd t1, 8(a0)

	# TODO: precomputation here, saving power of r vector state

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

	# load R and spread to 5 26-bit limbs: s0-4
	ld t0, 0(a0)
	ld t1, 8(a0)
	li t5, 0x0ffffffc0fffffff
	and t0, t0, t5
	li t5, 0x0ffffffc0ffffffc
	and t1, t1, t5
	scalar_extract_limbs t0 t1 s0 s1 s2 s3 s4 t5

	# pre-multiplied-by-5 scalars
	slli t4, s3, 2
	add t4, t4, s3
	slli t5, s4, 2
	add t5, t5, s4

	# a5 is vlmax-1 for e32m1
	li t0, -1
	vsetvli a5, t0, e32, m1, ta, mu
	addi a5, a5, -1 # vlmax-1
	# initialize vector to r^1
	vmv.v.x v6, s0
	vmv.v.x v7, s1
	vmv.v.x v8, s2
	vmv.v.x v9, s3
	vmv.v.x v10, s4

	# Do first iteration manually, as we can masked set r^2 instead of doing a second multiplication
	# a4 is current exp
	li a4, 1
	# set alternating mask pattern
	vid.v v1
	vrsub.vx v1, v1, a5
	vand.vx v1, v1, a4
	vmseq.vx v0, v1, a4
	slli a4, a4, 1

	# scalar-scalar 130bit mul: s0-4 = s0-4 * s0-4
	scalar_mul130 1 s0 s1 s2 s3 s4 t2 t3 t4 t5 s5 s6 s7 s8 s9 t0 t1

	vmv.v.i v11, 0 # no vmv with mask, so vor with 0
	vor.vx v6, v11, s0, v0.t
	vor.vx v7, v11, s1, v0.t
	vor.vx v8, v11, s2, v0.t
	vor.vx v9, v11, s3, v0.t
	vor.vx v10, v11, s4, v0.t

precomp:
	# compute mask (v0)
	# exp-1: 7,6,5,4,3,2,1,0 (a5)
	# r^1:   1,0,1,0,1,0,1,0
	# r^2:   1,1,0,0,1,1,0,0
	# r^4:   1,1,1,1,0,0,0,0
	vid.v v1
	vrsub.vx v1, v1, a5
	vand.vx v1, v1, a4
	vmseq.vx v0, v1, a4

	# vector-scalar masked 130bit mul: v6-10 = v6-10 * s0-4
	vec_mul130 vxm v6 v7 v8 v9 v10 s0 s1 s2 s3 s4 t2 t3 t4 t5 v12 v14 v16 v18 v20 v11 v22 vx ",v0.t"

	# scalar-scalar 130bit mul: s0-4 = s0-4 * s0-4
	scalar_mul130 2 s0 s1 s2 s3 s4 t2 t3 t4 t5 s5 s6 s7 s8 s9 t0 t1

	# end of precomp loop:
	slli a4, a4, 1 # double exponent
	blt a4, a5, precomp

	# set up state as initial leading zero step
	vmv.v.i v1, 0
	vmv.v.i v2, 0
	vmv.v.i v3, 0
	vmv.v.i v4, 0
	vmv.v.i v5, 0

	# From v11-14, separate out into 5 26-bit limbs: v20-v24
	.macro vec_split5
	li t0, 0x3ffffff
	vand.vx v20, v11, t0
	vsrl.vi v11, v11, 26
	vsll.vi v31, v12, 6
	vor.vv v11, v11, v31
	vand.vx v21, v11, t0
	vsrl.vi v12, v12, 20
	vsll.vi v31, v13, 12
	vor.vv v12, v12, v31
	vand.vx v22, v12, t0
	vsrl.vi v13, v13, 14
	vsll.vi v31, v14, 18
	vor.vv v13, v13, v31
	vand.vx v23, v13, t0
	vsrl.vi v24, v14, 8
	.endm

	# a2: bytes left
	# a4: blocks left
	srli a4, a2, 4
	# t1: blocks in initial step
	# use a full vector here, if blocks are a multiple of vector size
	addi a4, a4, -1
	and t1, a4, a5
	addi a4, a4, 1
	addi t1, t1, 1

	vsetvli t1, t1, e32, m1, ta, ma
	vlseg4e32.v v11, (a1)
	# increment pointer
	slli t0, t1, 4
	add a1, a1, t0
	sub a2, a2, t0
	vec_split5
	# add leading bit
	slli a3, a3, 24
	vor.vx v24, v24, a3

	li t0, -1
	vsetvli a5, t0, e32, m1, ta, ma
	sub t0, a5, t1
	slli a5, a5, 4 # block size in bytes
	vslideup.vx v1, v20, t0
	vslideup.vx v2, v21, t0
	vslideup.vx v3, v22, t0
	vslideup.vx v4, v23, t0
	vslideup.vx v5, v24, t0

vector_loop:
	beq a2, zero, end_vector_loop

	# multiply by r^vlmax
	vec_mul130 vx v1 v2 v3 v4 v5 s0 s1 s2 s3 s4 t2 t3 t4 t5 v12 v14 v16 v18 v20 v11 v22 vx

	# load in new data: v11-v14
	vlseg4e32.v v11, (a1)
	add a1, a1, a5
	sub a2, a2, a5
	vec_split5
	# add leading bit
	vor.vx v24, v24, a3

	# add into state
	vadd.vv v1, v1, v20
	vadd.vv v2, v2, v21
	vadd.vv v3, v3, v22
	vadd.vv v4, v4, v23
	vadd.vv v5, v5, v24

	j vector_loop
end_vector_loop:


	# multiply in [r^vlmax, r^(vlmax-1),... r^2, r]
	vsll.vi v27, v7, 2
	vadd.vv v27, v27, v7
	vsll.vi v28, v8, 2
	vadd.vv v28, v28, v8
	vsll.vi v29, v9, 2
	vadd.vv v29, v29, v9
	vsll.vi v30, v10, 2
	vadd.vv v30, v30, v10
	vec_mul130 vv v1 v2 v3 v4 v5 v6 v7 v8 v9 v10 v27 v28 v29 v30 v12 v14 v16 v18 v20 v11 v22 vv

	# vector reduction, into widened sum in case vector is huge
	vmv.v.i v6, 0
	vmv.v.i v7, 0
	vmv.v.i v8, 0
	vmv.v.i v9, 0
	vmv.v.i v10, 0
	vwredsum.vs v6, v1, v6
	vwredsum.vs v7, v2, v7
	vwredsum.vs v8, v3, v8
	vwredsum.vs v9, v4, v9
	vwredsum.vs v10, v5, v10
	# extract to scalars
	li t0, 1
	vsetvli zero, t0, e64, m1, ta, ma
	vmv.x.s s0, v6
	vmv.x.s s1, v7
	vmv.x.s s2, v8
	vmv.x.s s3, v9
	vmv.x.s s4, v10

	# carry through
	# t0=carry t1=mask
	li t0, 0
	li t1, 0x3ffffff
	.macro carry_scalar s
	add \s, \s, t0
	srli t0, \s, 26
	and \s, \s, t1
	.endm

	carry_scalar s0
	carry_scalar s1
	carry_scalar s2
	carry_scalar s3
	carry_scalar s4
	# carry *= 5
	slli t2, t0, 2
	add t0, t0, t2
	carry_scalar s0
	carry_scalar s1
	carry_scalar s2
	carry_scalar s3
	carry_scalar s4

	# collapse into contiguous 128 bits
	scalar_compress_limbs s0 s1 s2 s3 s4 t0

	sd s0, 0(a0)
	sd s1, 8(a0)

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

# void poly1305_emit(void *ctx, unsigned char mac[16],
#                           const u32 nonce[4])
vector_poly1305_emit:
	# load final accumulation
	ld t0, 0(a0)
	ld t1, 8(a0)
	# add in other half of key (after the carry)
	ld t2, 0(a2)
	ld t3, 8(a2)
	add t0, t0, t2
	sltu t2, t0, t2
	add t1, t1, t2
	add t1, t1, t3

	# write final signature
	sd t0, 0(a1)
	sd t1, 8(a1)

	ret
