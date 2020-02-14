# Might be easier to code this with C intrinsics,
# but rvv_vector.h seems to be closed source.

.global vector_poly1305
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

	# would it be more/less performant to do this by rows instead of columns?
	# vectors pipelining without requiring stalls etc
	# d0 column
	vwmulu.\v \d0, \a0, \b0 \mask
	vwmaccu.\v \d0, \b51, \a4 \mask
	vwmaccu.\v \d0, \b52, \a3 \mask
	vwmaccu.\v \d0, \b53, \a2 \mask
	vwmaccu.\v \d0, \b54, \a1 \mask

	# d1 column
	vwmulu.\v \d1, \a1, \b0 \mask
	vwmaccu.\v \d1, \b1, \a0 \mask
	vwmaccu.\v \d1, \b52, \a4 \mask
	vwmaccu.\v \d1, \b53, \a3 \mask
	vwmaccu.\v \d1, \b54, \a2 \mask

	# d2 column
	vwmulu.\v \d2, \a2, \b0 \mask
	vwmaccu.\v \d2, \b1, \a1 \mask
	vwmaccu.\v \d2, \b2, \a0 \mask
	vwmaccu.\v \d2, \b53, \a4 \mask
	vwmaccu.\v \d2, \b54, \a3 \mask

	# d3 column
	vwmulu.\v \d3, \a3, \b0 \mask
	vwmaccu.\v \d3, \b1, \a2 \mask
	vwmaccu.\v \d3, \b2, \a1 \mask
	vwmaccu.\v \d3, \b3, \a0 \mask
	vwmaccu.\v \d3, \b54, \a4 \mask

	# d4 column
	vwmulu.\v \d4, \a4, \b0 \mask
	vwmaccu.\v \d4, \b1, \a3 \mask
	vwmaccu.\v \d4, \b2, \a2 \mask
	vwmaccu.\v \d4, \b3, \a1 \mask
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
.macro scalar_mul130 a0 a1 a2 a3 a4 a51 a52 a53 a54 d0 d1 d2 d3 d4 carry tmp
	# d0 column
	mul \d0, \a0, \a0
	mul \tmp, \a51, \a4
	add \d0, \d0, \tmp
	mul \tmp, \a52, \a3
	add \d0, \d0, \tmp
	mul \tmp, \a53, \a2
	add \d0, \d0, \tmp
	mul \tmp, \a54, \a1
	add \d0, \d0, \tmp

	# d1 column
	mul \d1, \a1, \a0
	mul \tmp, \a1, \a0
	add \d1, \d1, \tmp
	mul \tmp, \a52, \a4
	add \d1, \d1, \tmp
	mul \tmp, \a53, \a3
	add \d1, \d1, \tmp
	mul \tmp, \a54, \a2
	add \d1, \d1, \tmp

	# d2 column
	mul \d2, \a2, \a0
	mul \tmp, \a1, \a1
	add \d2, \d2, \tmp
	mul \tmp, \a2, \a0
	add \d2, \d2, \tmp
	mul \tmp, \a53, \a4
	add \d2, \d2, \tmp
	mul \tmp, \a54, \a3
	add \d2, \d2, \tmp

	# d3 column
	mul \d3, \a3, \a0
	mul \tmp, \a1, \a2
	add \d3, \d3, \tmp
	mul \tmp, \a2, \a1
	add \d3, \d3, \tmp
	mul \tmp, \a3, \a0
	add \d3, \d3, \tmp
	mul \tmp, \a54, \a4
	add \d3, \d3, \tmp

	# d4 column
	mul \d4, \a4, \a0
	mul \tmp, \a1, \a3
	add \d4, \d4, \tmp
	mul \tmp, \a2, \a2
	add \d4, \d4, \tmp
	mul \tmp, \a3, \a1
	add \d4, \d4, \tmp
	mul \tmp, \a4, \a0
	add \d4, \d4, \tmp

	# Carry propagation
	# logic copied from https://github.com/floodyberry/poly1305-donna
	li \tmp, 0x3ffffff
	.macro carry_prop_scalar a d
	add \d, \d, \carry
	srli \carry, \d, 26
	and \a, \d, \tmp
	.endm

	li \carry, 0
	carry_prop_scalar \a0, \d0
	carry_prop_scalar \a1, \d1
	carry_prop_scalar \a2, \d2
	carry_prop_scalar \a3, \d3
	carry_prop_scalar \a4, \d4

	# wraparound carry continue
	slli \tmp, \carry, 2
	add \a0, \a0, \tmp
	add \a0, \a0, \carry
	# carry as much as the other mul code
	srli \carry, \a0, 26
	li \tmp, 0x3ffffff
	and \a0, \a0, \tmp
	add \a1, \a1, \carry

	.endm

# Argument mappings
# a0: const uint8_t* in
# a1: size_t len
# a2: const uint8_t[32] key
# a3: uint8_t[16] sig
# Register mappings (https://en.wikichip.org/wiki/risc-v/registers)
# r^vlmax: s0, s1, s2, s3, s4
# [r^vlmax, r^(vlmax-1), ... r^2, r]: v6, v7, v8, v9, v10
# current accumulated vector state: v1, v2, v3, v4, v5
vector_poly1305:
	# save registers
	sd s0, 0(sp)
	sd s1, 8(sp)
	sd s2, 16(sp)
	sd s3, 24(sp)
	sd s4, 32(sp)
	sd s5, 40(sp)
	sd s6, 48(sp)
	sd s7, 56(sp)
	sd s8, 64(sp)
	sd s9, 72(sp)
	sd s11, 80(sp)

	# assert input is a multiple of blocksize
	andi t0, a1, 0xf
	beq t0, zero, continue
	li t0, 0x3713 # magic error number
	sw t0, (a3)
	j return
continue:

	# load R and spread to 5 26-bit limbs: s0-4
	ld t0, 0(a2)
	ld t1, 8(a2)
	li t5, 0x0ffffffc0fffffff
	and t0, t0, t5
	li t5, 0x0ffffffc0ffffffc
	and t1, t1, t5
	li t5, 0x3ffffff
	and s0, t0, t5
	srli s1, t0, 26
	and s1, s1, t5
	srli s2, t0, 52
	slli t0, t1, 12
	or s2, s2, t0
	and s2, s2, t5
	srli s3, t1, 14
	and s3, s3, t5
	srli s4, t1, 40

	# a5 is vlmax-1 for e32m1
	li t0, -1
	vsetvli a5, t0, e32
	addi a5, a5, -1 # vlmax-1
	# initialize vector to r^1
	vmv.v.x v6, s0
	vmv.v.x v7, s1
	vmv.v.x v8, s2
	vmv.v.x v9, s3
	vmv.v.x v10, s4
	# a4 is current exp
	li a4, 1
	
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
	# TODO: first iteration can skip the vector-scalar mul, and just masked assign r^2

	# vector-scalar masked 130bit mul: v6-10 = v6-10 * s0-4
	# pre-multiplied-by-5 scalars
	slli t2, s1, 2
	add t2, t2, s1
	slli t3, s2, 2
	add t3, t3, s2
	slli t4, s3, 2
	add t4, t4, s3
	slli t5, s4, 2
	add t5, t5, s4
	vec_mul130 vxm v6 v7 v8 v9 v10 s0 s1 s2 s3 s4 t2 t3 t4 t5 v12 v14 v16 v18 v20 v11 v22 vx ",v0.t"

	# scalar-scalar 130bit mul: s0-4 = s0-4 * s0-4
	# pre-multiplied-by-5 scalars
	slli t2, s1, 2
	add t2, t2, s1
	slli t3, s2, 2
	add t3, t3, s2
	slli t4, s3, 2
	add t4, t4, s3
	slli t5, s4, 2
	add t5, t5, s4
	scalar_mul130 s0 s1 s2 s3 s4 t2 t3 t4 t5 s5 s6 s7 s8 s9 t0 t1

	# end of precomp loop:
	slli a4, a4, 1 # double exponent
	blt a4, a5, precomp

	# Store r*5 registers s1-4*5 in t2-5
	slli t2, s1, 2
	add t2, t2, s1
	slli t3, s2, 2
	add t3, t3, s2
	slli t4, s3, 2
	add t4, t4, s3
	slli t5, s4, 2
	add t5, t5, s4
	
	# store post-precomputation instruction counter
	rdinstret s11


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

	# set up state as initial leading zero step
	vmv.v.i v1, 0
	vmv.v.i v2, 0
	vmv.v.i v3, 0
	vmv.v.i v4, 0
	vmv.v.i v5, 0
	# a1: bytes left
	# a4: blocks left
	srli a4, a1, 4
	# t1: blocks in initial step
	# if blocks are a multiple of vector size, use a full vector here
	addi a4, a4, -1
	and t1, a4, a5
	addi a4, a4, 1
	addi t1, t1, 1

	vsetvli t1, t1, e32
	vlseg4e.v v11, (a0)
	# increment pointer
	slli t2, t1, 4
	add a0, a0, t2
	sub a1, a1, t2
	vec_split5
	# add leading bit
	# TODO: don't run vector version if we can't even fill the first vector
	li t0, 1<<24
	vor.vx v24, v24, t0

	li t0, -1
	vsetvli a5, t0, e32
	sub t0, a5, t1
	slli a5, a5, 4 # block size in bytes
	vslideup.vx v1, v20, t0
	vslideup.vx v2, v21, t0
	vslideup.vx v3, v22, t0
	vslideup.vx v4, v23, t0
	vslideup.vx v5, v24, t0


vector_loop:
	beq a1, zero, end_vector_loop

	# nothing should be running in the loop unless input size > vector size
	li t0, 0x42
	sw t0, (a3)
	j return

	# multiply by r^vlmax
	vec_mul130 vx v1 v2 v3 v4 v5 s0 s1 s2 s3 s4 t2 t3 t4 t5 v12 v14 v16 v18 v20 v11 v22 vx

	# load in new data: v11-v14
	vlseg4e.v v11, (a0)
	add a0, a0, a5
	sub a1, a1, a5
	vec_split5
	# add leading bit
	# TODO: support final non-full block correctly
	li t0, 1<<24
	vor.vx v24, v24, t0

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
	vsetvli zero, t0, e64
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
	# any remaining stuff to carry has to be in the 2 bits we don't care about, right?
	bne t0, zero, return

	# collapse into contiguous 128 bits (s0,s2)
	slli t0, s1, 26
	or s0, s0, t0
	slli t0, s2, 52
	or s0, s0, t0
	srli s2, s2, 12
	slli t0, s3, 14
	or s2, s2, t0
	slli t0, s4, 40
	or s2, s2, t0

	# add in other half of key (after the carry it seems)
	ld t0, 16(a2)
	ld t1, 24(a2)
	add s0, s0, t0
	sltu t0, s0, t0
	add s2, s2, t0
	add s2, s2, t1

	# write final signature
	sd s0, 0(a3)
	sd s2, 8(a3)

return:
	# restore registers
	mv a0, s11
	ld s0, 0(sp)
	ld s1, 8(sp)
	ld s2, 16(sp)
	ld s3, 24(sp)
	ld s4, 32(sp)
	ld s5, 40(sp)
	ld s6, 48(sp)
	ld s7, 56(sp)
	ld s8, 64(sp)
	ld s9, 72(sp)
	ld s11, 80(sp)
	ret

