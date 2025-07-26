/* Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License") ;
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

#include <errno.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>
#include "boring.h"
#include "openssl.h"

void println_hex(uint8_t* data, int size) {
  while (size > 0) {
    printf("%02x", *data);
    data++;
    size--;
  }
  printf("\n");
}

// TODO: test the vector doesn't write past the end
// test function with multiple length inputs (optional printing)
// test non-block sized lengths

extern uint32_t vlmax_u32();

const char* pass_str = "\x1b[32mPASS\x1b[0m";
const char* fail_str = "\x1b[31mFAIL\x1b[0m";

bool test_chacha(const uint8_t* data, size_t len, const uint8_t key[32], const uint8_t nonce[12], bool verbose) {
  extern void vector_chacha20(uint8_t *out, const uint8_t *in,
			      size_t in_len, const uint8_t key[32],
			      const uint8_t nonce[12], uint32_t counter);
#ifdef __riscv_zvkb
  extern void vector_chacha20_zvkb(uint8_t *out, const uint8_t *in,
			           size_t in_len, const uint8_t key[32],
			           const uint8_t nonce[12], uint32_t counter);
#endif
  uint8_t* golden = malloc(len);
  memset(golden, 0, len);
  boring_chacha20(golden, data, len, key, nonce, 0);

  uint8_t* vector = malloc(len + 4);
  memset(vector, 0, len+4);
  vector_chacha20(vector, data, len, key, nonce, 0);

  uint8_t* vector_rotate = malloc(len+4);
  memset(vector_rotate, 0, len+4);
#ifdef __riscv_zvkb
  vector_chacha20_zvkb(vector_rotate, data, len, key, nonce, 0);
#endif

  bool pass = memcmp(golden, vector, len) == 0 && memcmp(golden, vector_rotate, len) == 0;

  if (verbose || !pass) {
    printf("golden: ");
    println_hex(golden, 32);
    printf("\nvector: ");
    println_hex(vector, 32);
    printf("\nrotate: ");
    println_hex(vector_rotate, 32);
    printf("\n");
  }

  uint32_t past_end = vector[len];
  if (past_end != 0) {
    printf("vector wrote past end %08x\n", past_end);
    pass = false;
  }
  past_end = vector_rotate[len];
  if (past_end != 0) {
    printf("vector w/ rotate wrote past end %08x\n", past_end);
    pass = false;
  }

  free(golden);
  free(vector);
  free(vector_rotate);

  return pass;
}

bool test_chachas(FILE* f) {
  int len = 64*1024 - 11;
  uint8_t* data = malloc(len);
  uint32_t rand = 1;
  for (int i = 0; i < len; i++) {
    rand *= 101;
    rand %= 16777213; // random prime
    data[i] = (uint8_t)(rand);
  }
  uint8_t key[32] = "Setec astronomy;too many secrets";
  uint8_t nonce[12] = "BurnAfterUse";
  int counter = 0;

  bool pass = test_chacha(data, len, key, nonce, false);

  if (pass) {
    for (int i = 1, len = 1; len < 1000; len += i++) {
      fread(key, 32, 1, f);
      fread(nonce, 12, 1, f);
      if (!test_chacha(data, len, key, nonce, false)) {
	printf("Failed with len=%d\n", len);
	pass = false;
	break;
      }
    }
  }

  if (pass) {
    printf("VLEN=%d chacha %s\n", vlmax_u32()*32, pass_str);
  } else {
    printf("VLEN=%d chacha %s\n", vlmax_u32()*32, fail_str);
  }
  return pass;
}

extern void vector_poly1305_init(void *ctx, const unsigned char key[16]);
extern void vector_poly1305_blocks(void *ctx, const unsigned char *inp,
		  size_t len, uint32_t padbit);
extern void vector_poly1305_single_blocks(void *ctx, const unsigned char *inp,
		  size_t len, uint32_t padbit);
extern void vector_poly1305_emit(void *ctx, unsigned char mac[16],
		  const uint8_t nonce[16]);

void vector_poly1305(const uint8_t* in, size_t len,
		const uint8_t key[32], uint8_t sig[16],
		void (*blocks)(void *ctx, const unsigned char *inp, size_t len, uint32_t padbit)) {
  double state[24];  // openssl's scratch space
  vector_poly1305_init(&state, key);
  size_t block_len = len &~ 15;
  blocks(&state, in, block_len, 1);
  if (len > block_len) {
    size_t tail_len = len & 15;
    uint8_t buffer[16];
    memset(buffer, 0, 16);
    memcpy(buffer, in+block_len, tail_len);
    buffer[tail_len] = 1;
    blocks(&state, buffer, 16, 0);
  }
  vector_poly1305_emit(&state, sig, key+16);
}

bool test_poly(const uint8_t* data, size_t len, const uint8_t key[32], bool verbose) {
  poly1305_state state;
  uint8_t sig[16];
  boring_poly1305_init(&state, key);
  boring_poly1305_update(&state, data, len);
  boring_poly1305_finish(&state, sig);

  uint8_t sig2[16];
  vector_poly1305(data, len, key, sig2, vector_poly1305_blocks);

  uint8_t sig3[16];
  vector_poly1305(data, len, key, sig3, vector_poly1305_single_blocks);

  bool pass = memcmp(sig, sig2, 16) == 0 && memcmp(sig, sig3, 16) == 0;

  if (verbose || !pass) {
    printf("boring mac: ");
    println_hex(sig, 16);
    printf("vector mac: ");
    println_hex(sig2, 16);
    printf("block1 mac: ");
    println_hex(sig3, 16);
  }

  return pass;
}

bool test_polys(FILE* f) {
  const int big_len = 64*1024;
  uint8_t *max_bits = malloc(big_len);
  memset(max_bits, 0xff, big_len);
  const uint8_t one[32] = {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  const uint8_t key[32] = {1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 144, 169, 196, 225, 255,
  			   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  const uint8_t data[272] = "Setec astronomy;too many secrets";
  // Test with all bits set in inputs to trigger as many carries as possible.
  bool pass = test_poly(max_bits, big_len, max_bits, false);

  if (pass) {
    // random test
    const int max_len = 1000;
    uint8_t rand[max_len];
    for (int len = 11; len <= max_len; len += 17) {
      fread((uint8_t*)key, 32, 1, f);
      fread((uint8_t*)rand, len, 1, f);
      if (!test_poly(data, len, key, false)) {
        printf("failed random input len=%d\n", len);
        pass = false;
        break;
      }
    }
  }

  if (pass) {
    printf("VLEN=%d poly   %s\n", vlmax_u32()*32, pass_str);
  } else {
    printf("VLEN=%d poly   %s\n", vlmax_u32()*32, fail_str);
  }

  free(max_bits);
  return pass;
}

void run_benchmarks(size_t input_size, size_t num_runs) {
  struct perf_event_attr perf;
  memset(&perf, 0, sizeof(struct perf_event_attr));
  perf.type = PERF_TYPE_HARDWARE;
  perf.size = sizeof(struct perf_event_attr);
  perf.config = PERF_COUNT_HW_CPU_CYCLES;
  perf.disabled = 1;
  perf.exclude_kernel = 1;
  perf.exclude_hv = 1;
  int fd = syscall(SYS_perf_event_open, &perf, 0, -1, -1, 0);
  if (fd == -1) {
    fprintf(stderr, "Error opening perf event: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  struct rusage time_stuff;

  double vector_state[24];
  poly1305_state boring_state;
  struct poly1305_context openssl_state;
  uint8_t key[32], sig[16];
  uint8_t* data = malloc(input_size);
  memset(key, 0xaa, 32);
  memset(data, 0x55, input_size);


  // Benchmark init.
  // Warm up the instruction cache.
  vector_poly1305_init(&vector_state, key);

  getrusage(RUSAGE_SELF, &time_stuff);
  uint64_t micros_start = (uint64_t)(time_stuff.ru_utime.tv_usec) + 1000000*(uint64_t)(time_stuff.ru_utime.tv_sec);
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

  int init_runs = 100000;
  for (int i = 0; i < init_runs; i++) {
    vector_poly1305_init(&vector_state, key);
  }

  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  getrusage(RUSAGE_SELF, &time_stuff);
  uint64_t micros_end = (uint64_t)(time_stuff.ru_utime.tv_usec) + 1000000*(uint64_t)(time_stuff.ru_utime.tv_sec);
  uint64_t micros = micros_end - micros_start;

  uint64_t cycles;
  if (read(fd, &cycles, sizeof(cycles)) == -1) {
    fprintf(stderr, "Error reading perf event: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  printf("poly init\t\t\t%lu ns\t\t%lu cycles\n", micros*1000/init_runs, cycles/init_runs);


  // Benchmark boring.
  // Warm up the instruction cache.
  boring_poly1305_init(&boring_state, key);
  boring_poly1305_update(&boring_state, key, 32);
  boring_poly1305_finish(&boring_state, sig);

  getrusage(RUSAGE_SELF, &time_stuff);
  micros_start = (uint64_t)(time_stuff.ru_utime.tv_usec) + 1000000*(uint64_t)(time_stuff.ru_utime.tv_sec);
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

  for (int i = 0; i < num_runs; i++) {
    boring_poly1305_init(&boring_state, key);
    boring_poly1305_update(&boring_state, data, input_size);
    boring_poly1305_finish(&boring_state, sig);
  }

  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  getrusage(RUSAGE_SELF, &time_stuff);
  micros_end = (uint64_t)(time_stuff.ru_utime.tv_usec) + 1000000*(uint64_t)(time_stuff.ru_utime.tv_sec);
  micros = micros_end - micros_start;

  if (read(fd, &cycles, sizeof(cycles)) == -1) {
    fprintf(stderr, "Error reading perf event: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  printf("poly boring\t% 5ld bytes\t%.1f MB/s\t%.2f cycles/byte\n", input_size,
  	(double)(input_size*num_runs)/micros,
  	(double)(cycles)/(input_size*num_runs));


  // Benchmark openssl single.
  // Warm up the instruction cache.
  Poly1305_Init(&openssl_state, key);
  Poly1305_Update(&openssl_state, key, 32);
  Poly1305_Final(&openssl_state, sig);

  getrusage(RUSAGE_SELF, &time_stuff);
  micros_start = (uint64_t)(time_stuff.ru_utime.tv_usec) + 1000000*(uint64_t)(time_stuff.ru_utime.tv_sec);
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

  for (int i = 0; i < num_runs; i++) {
    Poly1305_Init(&openssl_state, key);
    Poly1305_Update(&openssl_state, data, input_size);
    Poly1305_Final(&openssl_state, sig);
  }

  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  getrusage(RUSAGE_SELF, &time_stuff);
  micros_end = (uint64_t)(time_stuff.ru_utime.tv_usec) + 1000000*(uint64_t)(time_stuff.ru_utime.tv_sec);
  micros = micros_end - micros_start;

  if (read(fd, &cycles, sizeof(cycles)) == -1) {
    fprintf(stderr, "Error reading perf event: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  printf("poly openssl\t% 5ld bytes\t%.1f MB/s\t%.2f cycles/byte\n", input_size,
  	(double)(input_size*num_runs)/micros,
  	(double)(cycles)/(input_size*num_runs));


  // Benchmark vector single.
  // Warm up the instruction cache.
  vector_poly1305(key, 32, key, sig, vector_poly1305_single_blocks);

  getrusage(RUSAGE_SELF, &time_stuff);
  micros_start = (uint64_t)(time_stuff.ru_utime.tv_usec) + 1000000*(uint64_t)(time_stuff.ru_utime.tv_sec);
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

  for (int i = 0; i < num_runs; i++) {
    vector_poly1305(data, input_size, key, sig, vector_poly1305_single_blocks);
  }

  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  getrusage(RUSAGE_SELF, &time_stuff);
  micros_end = (uint64_t)(time_stuff.ru_utime.tv_usec) + 1000000*(uint64_t)(time_stuff.ru_utime.tv_sec);
  micros = micros_end - micros_start;

  if (read(fd, &cycles, sizeof(cycles)) == -1) {
    fprintf(stderr, "Error reading perf event: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  printf("poly vsingle\t% 5ld bytes\t%.1f MB/s\t%.2f cycles/byte\n", input_size,
  	(double)(input_size*num_runs)/micros,
  	(double)(cycles)/(input_size*num_runs));


  // Benchmark vector blocks.
  // Warm up the instruction cache.
  vector_poly1305(key, 32, key, sig, vector_poly1305_blocks);

  getrusage(RUSAGE_SELF, &time_stuff);
  micros_start = (uint64_t)(time_stuff.ru_utime.tv_usec) + 1000000*(uint64_t)(time_stuff.ru_utime.tv_sec);
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

  for (int i = 0; i < num_runs; i++) {
    vector_poly1305(data, input_size, key, sig, vector_poly1305_blocks);
  }

  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  getrusage(RUSAGE_SELF, &time_stuff);
  micros_end = (uint64_t)(time_stuff.ru_utime.tv_usec) + 1000000*(uint64_t)(time_stuff.ru_utime.tv_sec);
  micros = micros_end - micros_start;

  if (read(fd, &cycles, sizeof(cycles)) == -1) {
    fprintf(stderr, "Error reading perf event: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  printf("poly vblocks\t% 5ld bytes\t%.1f MB/s\t%.2f cycles/byte\n", input_size,
  	(double)(input_size*num_runs)/micros,
  	(double)(cycles)/(input_size*num_runs));
} 

int main(int argc, char *const argv[]) {
  bool benchmark = false;
  int n = 1024;
  int c;
  while ((c = getopt(argc, argv, "bn:")) != -1) {
    switch (c) {
      case 'b':
        benchmark = true;
        break;
      case 'n':
        n = atoi(optarg);
        break;
    }
  }
  if (benchmark) {
    if (n < 1) n = 1;
    int runs = (100<<20)/(n+100);
    if (runs < 1) runs = 1;
    run_benchmarks(n, runs);
  } else {
    FILE* rand = fopen("/dev/urandom", "r");
    bool pass = test_chachas(rand);
    if (!test_polys(rand)) { pass = false; }
    fclose(rand);
    return pass ? 0 : 1;
  }
}
